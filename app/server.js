const pg = require("pg");
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const sharp = require("sharp");

const { hashPassword, validatePassword } = require("./passwordUtil");
const {
    createSession,
    setSessionCookie,
    getSession,
    deleteSession,
    clearSessionCookie,
    authMiddleware,
    startTokenCleanup
} = require("./sessionUtil");

const app = express();
const port = process.env.PORT || 3000;

const LOGIN_PAGE = "/src/login.html";
const HOME_PAGE = "/index";
const IMAGE_DIR = path.join(__dirname, "public", "images");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const env = require("../env.json");
const pool = new pg.Pool(env);

pool.connect()
    .then(function (client) {
        console.log(`Connected to database ${env.database}`);
        client.release();
    })
    .catch(function (err) {
        console.error("Database connection failed:", err.message);
    });

// keep the upload in memory; sharp validates it and writes the final file
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 2 * 1024 * 1024, files: 1 },
    fileFilter: (req, file, cb) => {
        if (["image/png", "image/jpeg", "image/webp"].includes(file.mimetype)) {
            return cb(null, true);
        }
        cb(new Error("INVALID_TYPE"));
    }
});

function profilePicPath(id) {
    return path.join(IMAGE_DIR, `profile_${id}.png`);
}

app.use(express.json());
app.use(cookieParser());
startTokenCleanup();
app.use(express.static(path.join(__dirname, "public")));

// Page middleware: redirects to login instead of returning JSON,
// and exposes the session as `user` in every EJS template.
function requireLogin(req, res, next) {
    const session = getSession(req.cookies && req.cookies.token);
    if (!session) return res.redirect(LOGIN_PAGE);
    req.session = session;
    res.locals.user = session;
    next();
}

const pages = {
    index:           { view: "index",        title: "Home" },
    auctions:        { view: "auctions",     title: "Auctions" },
    trade:           { view: "trade",        title: "Trade" },
    friends:         { view: "friends",      title: "Friends" },
    notifications:   { view: "notif",        title: "Notifications" },
    listings:        { view: "listings",     title: "My Listings" },
    settings:        { view: "settings",     title: "Settings" },
    itemView:        { view: "item-view",    title: "Item View" },
    auctionItemView: { view: "auction-view", title: "Auction Item View" }
};

// signup (multipart form: text fields + optional profile_pic file)
app.post("/signup", (req, res, next) => {
    upload.single("profile_pic")(req, res, (err) => {
        if (!err) return next();
        if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({ message: "Profile picture must be 2 MB or smaller" });
        }
        if (err.message === "INVALID_TYPE") {
            return res.status(400).json({ message: "Profile picture must be a PNG, JPG, or WebP" });
        }
        console.error(err);
        return res.status(400).json({ message: "Could not upload profile picture" });
    });
}, async (req, res) => {
    const { username, email, password, confirm_pass } = req.body || {};

    if (typeof username !== "string" || username.length < 1 || username.length > 25) {
        return res.status(400).json({ message: "Please enter valid username" });
    }
    if (typeof email !== "string" || email.length < 1) {
        return res.status(400).json({ message: "Please enter valid email" });
    }
    if (typeof password !== "string" || password.length < 1 ||
        typeof confirm_pass !== "string" || confirm_pass.length < 1) {
        return res.status(400).json({ message: "Password fields cannot be left empty" });
    }
    if (password !== confirm_pass) {
        return res.status(400).json({ message: "Password must match" });
    }

    let picId = null;   // null = blank placeholder image

    try {
        const hashedPassword = await hashPassword(password);

        if (req.file) {
            picId = crypto.randomBytes(16).toString("hex");
            try {
                await sharp(req.file.buffer)
                    .resize(256, 256, { fit: "cover" })
                    .png()
                    .toFile(profilePicPath(picId));
            } catch (imgErr) {
                // sharp rejects files that aren't really images
                picId = null;
                return res.status(400).json({ message: "That file is not a valid image" });
            }
        }

        const inserted = await pool.query(
            `INSERT INTO accounts (username, email, password_hash, profile_pic_id)
             VALUES ($1, $2, $3, $4)
             RETURNING id`,
            [username, email, hashedPassword, picId]
        );

        // log the new user in right away
        setSessionCookie(res, createSession(inserted.rows[0].id, username, picId));
        return res.status(200).json({ message: "Account Created!" });
    } catch (error) {
        console.error(error);

        // don't leave an orphaned image if the insert failed
        if (picId) fs.unlink(profilePicPath(picId), () => {});

        // 23505 = unique_violation
        if (error.code === "23505") {
            if (error.constraint === "accounts_email_key") {
                return res.status(409).json({ message: "An account already exists with that email" });
            }
            if (error.constraint === "accounts_username_key") {
                return res.status(409).json({ message: "An account already exists with that username" });
            }
            return res.status(409).json({ message: "An account already exists with that email or username" });
        }

        return res.status(500).json({ message: "Could not create account" });
    }
});

// account
app.get("/account", requireLogin, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT username, email, profile_pic_id, bio FROM accounts WHERE id = $1",
            [req.session.accountId]
        );

        if (result.rows.length === 0) {
            // account was deleted while the session was still active
            deleteSession(req.cookies.token);
            clearSessionCookie(res);
            return res.redirect(LOGIN_PAGE);
        }

        res.render("account", { active: "account", account: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).send("Could not load your account");
    }
});

// login
app.post("/login", async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || username.length < 1 || username.length > 25) {
        return res.status(400).json({ message: "Please enter valid username" });
    }
    if (typeof password !== "string" || password.length < 1) {
        return res.status(400).json({ message: "Please enter password" });
    }

    try {
        const result = await pool.query(
            "SELECT id, username, password_hash, profile_pic_id FROM accounts WHERE username = $1",
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const account = result.rows[0];

        let validPassword = false;
        try {
            validPassword = await validatePassword(password, account.password_hash);
        } catch (err) {
            validPassword = false;   // malformed stored hash
        }

        if (!validPassword) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        setSessionCookie(
            res,
            createSession(account.id, account.username, account.profile_pic_id)
        );
        return res.status(200).json({ message: "Login successful" });
    } catch (error) {
        console.error("Login database error:", error);
        return res.status(500).json({ message: "Something went wrong" });
    }
});

// reset password
// NOTE: still unauthenticated. Anyone who knows an email can change that
// account's password. Add an emailed token or require login before launch.
app.post("/reset-password", async (req, res) => {
    const { email, password, confirm_pass } = req.body || {};

    if (typeof email !== "string" || email.length < 1) {
        return res.status(400).json({ message: "Please enter valid email" });
    }
    if (typeof password !== "string" || password.length < 1) {
        return res.status(400).json({ message: "Please enter a new password" });
    }
    if (password !== confirm_pass) {
        return res.status(400).json({ message: "Passwords must match" });
    }

    try {
        const hashedPassword = await hashPassword(password);

        const result = await pool.query(
            "UPDATE accounts SET password_hash = $1 WHERE email = $2",
            [hashedPassword, email]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ message: "No account found with that email" });
        }

        return res.status(200).json({ message: "Password updated!" });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Could not reset password" });
    }
});

// logout
app.post("/logout", (req, res) => {
    deleteSession(req.cookies && req.cookies.token);
    clearSessionCookie(res);
    res.redirect(LOGIN_PAGE);
});

// current user info for client-side scripts
app.get("/api/session", authMiddleware, (req, res) => {
    res.json({
        username: req.session.username,
        profilePicId: req.session.profilePicId
    });
});

// item catalog
app.get("/items", authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, brand, series, image, rarity
             FROM items
             ORDER BY brand, series, name`
        );
        res.status(200).json(result.rows);
    } catch (error) {
        console.error("Error fetching items:", error);
        res.status(500).json({ message: "Could not retrieve collectibles" });
    }
});

// add item to the logged-in user's collection
app.post("/itemView", authMiddleware, async (req, res) => {
    const itemID = Number.parseInt(req.body && req.body.itemID, 10);
    if (!Number.isInteger(itemID)) {
        return res.status(400).json({ success: false, message: "Invalid item" });
    }

    try {
        await pool.query(
            "INSERT INTO collection_items (account_id, item_id) VALUES ($1, $2)",
            [req.session.accountId, itemID]
        );
        res.status(200).json({ success: true, message: "Added to collection" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Could not add to collection" });
    }
});

// place a bid (placeholder: bidder comes from the session, never from the body)
app.post("/auctionItemView", authMiddleware, async (req, res) => {
    try {
        const { bid } = req.body || {};
        console.log(`Bid from account ${req.session.accountId}:`, bid);

        res.status(200).json({ success: true, message: "Place bid placeholder" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Failed to place bid." });
    }
});

// "/" goes to the home page (logged-out users get bounced to login by requireLogin)
app.get("/", (req, res) => res.redirect(HOME_PAGE));

// page routes (registered last)
Object.entries(pages).forEach(([route, { view, title }]) => {
    app.get("/" + route, requireLogin, (req, res) => {
        const viewExists = fs.existsSync(path.join(__dirname, "views", view + ".ejs"));

        if (viewExists) {
            res.render(view, { active: route });
        } else {
            res.status(404).send(`${title} page coming soon`);
        }
    });
});

app.listen(port, "0.0.0.0", () => {
    console.log(`Listening on port ${port}`);
});