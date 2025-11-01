import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { Pool } from "pg";
import dotenv from "dotenv";
import multer from "multer";
import path from "path";
import fs from "fs";
import { S3Client } from "@aws-sdk/client-s3";
import multerS3 from "multer-s3";
import bcrypt from "bcrypt";

dotenv.config();
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID!,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY!,
    sessionToken: process.env.AWS_SESSION_TOKEN!,
  },
});

const uploadS3 = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_BUCKET_NAME!,
    contentType: multerS3.AUTO_CONTENT_TYPE,
    // acl removed
    key: (req, file, cb) => {
      const timestamp = Date.now();
      const ext = path.extname(file.originalname);
      const filename = `${timestamp}-${Math.round(Math.random() * 1e9)}${ext}`;
      cb(null, filename);
    },
  }),
});

const uploadProduct = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_BUCKET_NAME!,
    contentType: multerS3.AUTO_CONTENT_TYPE,
    key: (req, file, cb) => {
      const timestamp = Date.now();
      const ext = path.extname(file.originalname);
      const filename = `products/${timestamp}-${Math.round(Math.random() * 1e9)}${ext}`;
      cb(null, filename);
    },
  }),
});

const upload = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_BUCKET_NAME!,
    contentType: multerS3.AUTO_CONTENT_TYPE,
    // acl removed
    key: (req, file, cb) => {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      const ext = path.extname(file.originalname);
      cb(null, `slips/${uniqueSuffix}${ext}`);
    },
  }),
});

const uploadCustom = multer({
  storage: multerS3({
    s3: s3,
    bucket: process.env.AWS_BUCKET_NAME!,
    // acl removed
    key: (req, file, cb) => {
      const filename = `custom_products/${Date.now()}-${Math.round(Math.random() * 1e9)}-${file.originalname}`;
      cb(null, filename);
    },
  }),
});




const app = express();

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

const allowedOrigins = [
  "http://localhost:5173",
  "http://44.222.93.126:5173"
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
}));


app.use(express.json());

const session = require("express-session");

// Add session types
declare module "express-session" {
  interface SessionData {
    user?: {
      email: string;
    };
    cart?: any[];
  }
}


// Setup session
app.use(
  session({
    name: "sid", // cookie name
    secret: process.env.SESSION_SECRET || "mysecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24,
      sameSite: "lax",
      secure: false,
    },
  })
);

// res.locals
app.use((req, res, next) => {
  res.locals.user = req.session.user ?? null;
  res.locals.cart = req.session.cart ?? [];
  next();
});

// Middleware
function requireLogin(req: Request, res: Response, next: NextFunction) {
  if (!req.session.user) {
    return res.status(401).json({ message: "Please login first" });
  }
  next();
}

// db from .env
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: Number(process.env.DB_PORT) || 5432,
  ssl: { rejectUnauthorized: false }
});


// dir setup
const uploadDirs = ["uploads", "uploads/products", "uploads/slips", "uploads/custom_products/", "uploads/user_profiles/"];
uploadDirs.forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});
app.use("/uploads", express.static(path.join(__dirname, "uploads")));


app.get("/api/session", (req: Request, res: Response) => {
  console.log("SESSION OBJECT:", req.session);
  if (req.session.user) {
    res.json({ user: req.session.user });
  } else {
    res.status(401).json({ error: "Not logged in" });
  }
});

// User
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM main_userinfo');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// sign up
app.post('/api/signup', async (req, res) => {
    const { username, name, email, password, phone, gender, dob, profileImage } = req.body;

    try {
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10); // 10 salt rounds

      const query = `
        INSERT INTO main_userinfo (username, name, email, password, phone, gender, dob, "profileImage")
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *;
      `;
      const values = [username, name, email, hashedPassword, phone, gender, dob, profileImage];
      const result = await pool.query(query, values);

      req.session.user = email;
      res.json({ message: 'Signup successful', redirect: '/Login' });
    } catch (err: any) {
      console.error(err);
      res.status(400).json({ message: err.detail || 'Signup failed' });
    }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      'SELECT * FROM main_userinfo WHERE email=$1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    delete user.password; // don't send password to frontend
    req.session.user = user; 
    res.json({ message: 'Login successful', user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }

});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ message: 'Logout failed' });
    res.clearCookie("sid");
    res.json({ message: 'Logout successful' });
  });
});
app.put("/api/update-user", requireLogin, async (req, res) => {
  const sessionUser = req.session.user;

  // Ensure sessionUser is an object with email
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

  if (!userEmail) {
    return res.status(401).json({ message: "Not logged in" });
  }

  const { username, name, phone, email, currentPassword, newPassword } = req.body;

  try {
    // Fetch user from DB
    const result = await pool.query("SELECT * FROM main_userinfo WHERE email = $1", [userEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const dbUser = result.rows[0];

    // Only check password if user wants to change it
    let finalPassword = dbUser.password;
    if (newPassword) {
      if (newPassword) {
        if (!currentPassword) return res.status(400).json({ message: "Current password required" });
        
        const match = await bcrypt.compare(currentPassword, dbUser.password);
        if (!match) return res.status(400).json({ message: "Current password is incorrect" });
        
        finalPassword = await bcrypt.hash(newPassword, 10); // hash new password
      }

      finalPassword = newPassword;
    }

    // Update query
    const updatedResult = await pool.query(
      `
      UPDATE main_userinfo
      SET username=$1, name=$2, phone=$3, email=$4, password=$5
      WHERE email=$6
      RETURNING *;
      `,
      [username, name, phone, email || dbUser.email, finalPassword, userEmail]
    );

    const updatedUser = updatedResult.rows[0];
    delete updatedUser.password;

    // Update session
    req.session.user = updatedUser;

    res.json({ message: "User updated successfully", user: updatedUser });
  } catch (err: any) {
    console.error("Update user error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/api/check-admin", (req, res) => {
  const sessionUser = req.session.user;
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

  if (!userEmail) {
    return res.status(401).json({ message: "Not logged in" });
  }

  pool.query(
    'SELECT * FROM main_providerlist WHERE email_id = $1',
    [userEmail]
  )
  .then(result => {
    const isAdmin = result.rows.length > 0;
    res.json({ isAdmin });
  })
  .catch(err => {
    console.error("Check admin error:", err);
    res.status(500).json({ message: "Internal server error" });
  });
});


// --------------PRODUCT---------------

const query_products = `
      SELECT 
        p.*,
        pi."imgURL",
        c."categoryName" AS "categoryName",
        COALESCE(array_agg(sc."subName") FILTER (WHERE sc."subName" IS NOT NULL), '{}') AS "subcategories"
      FROM main_productdetail p
      LEFT JOIN main_productcategory c ON p."category_id" = c.id
      LEFT JOIN main_productdetail_subcategories pd_sc ON pd_sc."productdetail_id" = p."productID"
      LEFT JOIN main_subcategory sc ON pd_sc."subcategory_id" = sc.id
      LEFT JOIN LATERAL (
        SELECT "imgURL"
        FROM main_productimage
        WHERE product_id = p."productID"
        LIMIT 1
      ) pi ON true
      WHERE p."productID" NOT LIKE '%CUSTOM%'
      GROUP BY p."productID", pi."imgURL", c."categoryName"
    `

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(query_products);

    res.json(result.rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Products: Failed to fetch" });
  }
});

app.get("/api/products_random", async (req, res) => {
  try {
    const result = await pool.query(
      query_products + `
      ORDER BY RANDOM()
      LIMIT 10
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Products_rd: Failed to fetch" });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `
      SELECT p.*, c."categoryName", s."subName", pi."imgURL"
      FROM main_productdetail p
      LEFT JOIN main_productcategory c ON p."category_id" = c.id
      LEFT JOIN main_productdetail_subcategories ps ON p."productID" = ps."productdetail_id"
      LEFT JOIN main_subcategory s ON ps."subcategory_id" = s.id
      LEFT JOIN LATERAL (
        SELECT "imgURL"
        FROM main_productimage
        WHERE product_id = p."productID"
        LIMIT 1
      ) pi ON true
      WHERE p."productID" = $1
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Products/:id: Failed to fetch" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch product" });
  }
});

app.get("/api/products/search/:query", async (req, res) => {
  try {
    const { query } = req.params;
    const result = await pool.query(
      `
      SELECT "productID", "productName"
      FROM main_productdetail
      WHERE "productName" ILIKE $1
      LIMIT 10
      `,
      [`%${query}%`]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Failed to search products" });
  }
});

// Add product
app.post("/api/products", uploadProduct.single("image"), async (req, res) => {
  try {
    const { productName, price, description, size, material, category_id, stock, is_available } = req.body;

    const newId = `PROD_${Date.now()}`;
    // S3 upload returns `req.file.key` for the object path
    const imagePath = req.file ? (req.file as any).key : null;

    // Insert product
    await pool.query(
      `INSERT INTO main_productdetail (
        "productID", "productName", price, description, size, material, category_id, stock, is_available, "addedDate", "updatedDate"
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())`,
      [newId, productName, price, description, size, material, category_id, stock, is_available]
    );

    // Insert image
    if (imagePath) {
      await pool.query(
        `INSERT INTO main_productimage (product_id, "imgURL") VALUES ($1, $2)`,
        [newId, imagePath]
      );
    }

    res.json({ success: true, message: "Product added successfully", productID: newId });
  } catch (err) {
    console.error("Error adding product:", err);
    res.status(500).json({ error: "Failed to add product" });
  }
});

// Update product
app.put("/api/products/:id", uploadProduct.single("image"), async (req, res) => {
  try {
    const { id } = req.params;
    const { productName, price, description, size, material, category_id, stock, is_available } = req.body;

    // Check if product exists
    const existing = await pool.query(`SELECT * FROM main_productdetail WHERE "productID" = $1`, [id]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }

    // Update product
    await pool.query(
      `UPDATE main_productdetail
       SET "productName" = $1,
           price = $2,
           description = $3,
           size = $4,
           material = $5,
           category_id = $6,
           stock = $7,
           is_available = $8,
           "updatedDate" = NOW()
       WHERE "productID" = $9`,
      [productName, price, description, size, material, category_id, stock, is_available === "true" || is_available === true, id]
    );

    // Update image if uploaded
    if (req.file) {
      const imagePath = `/uploads/products/${req.file.filename}`;

      // Check if product already has an image
      const imgExist = await pool.query(
        `SELECT * FROM main_productimage WHERE product_id = $1 LIMIT 1`,
        [id]
      );

      if (imgExist.rows.length > 0) {
        // Update existing image
        await pool.query(
          `UPDATE main_productimage SET "imgURL" = $1 WHERE product_id = $2`,
          [imagePath, id]
        );
      } else {
        // Insert new image
        await pool.query(
          `INSERT INTO main_productimage (product_id, "imgURL") VALUES ($1, $2)`,
          [id, imagePath]
        );
      }
    }

    res.json({ success: true, message: "Product updated successfully" });
  } catch (err) {
    console.error("Error updating product:", err);
    res.status(500).json({ error: "Failed to update product" });
  }
});

// Delete product
app.delete("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Delete image
    const imgRes = await pool.query(`SELECT "imgURL" FROM main_productimage WHERE product_id=$1`, [id]);
    if (imgRes.rows.length > 0) {
      const imgPath = imgRes.rows[0].imgURL;
      if (imgPath && fs.existsSync(path.join(__dirname, imgPath))) {
        fs.unlinkSync(path.join(__dirname, imgPath));
      }
      await pool.query(`DELETE FROM main_productimage WHERE product_id=$1`, [id]);
    }

    // Delete product
    await pool.query(`DELETE FROM main_productdetail WHERE "productID"=$1`, [id]);

    res.json({ success: true, message: "Product deleted successfully" });
  } catch (err) {
    console.error("Error deleting product:", err);
    res.status(500).json({ error: "Failed to delete product" });
  }
});

// --------------PRODUCT---------------
// --------------categories---------------

app.get("/api/categories", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM main_productcategory
      ORDER BY id DESC;
      `);
    res.json(result.rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: " Categories: Failed to fetch" });
  }
});
app.get("/api/categories/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(`
      SELECT * FROM main_productcategory
      WHERE id=$1;`, [id]);
    res.json(result.rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: " Categories: Failed to fetch" });
  }
});

app.post("/api/categories", async (req, res) => {
  try {
    const { categoryName, description } = req.body;

    if (!categoryName || categoryName.trim() === "") {
      return res.status(400).json({ error: "Category name is required" });
    }

    const query = `
      INSERT INTO main_productcategory ("categoryName", description)
      VALUES ($1, $2)
      RETURNING *;
    `;

    const result = await pool.query(query, [categoryName.trim(), description || null]);
    res.status(201).json({ message: "Category added successfully", category: result.rows[0] });

  } catch (err) {
    console.error("Error adding category:", err);
    res.status(500).json({ error: "Failed to add category" });
  }
});

app.delete("/api/categories/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const query = `
      DELETE FROM main_productcategory
      WHERE id = $1
      RETURNING *;
    `;
    const user = res.locals.user || null;
    const result = await pool.query(query, [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Category not found" });
    }

    res.json({ message: "Category deleted successfully", deleted: result.rows[0] });
  } catch (err) {
    console.error("Error deleting category:", err);
    res.status(500).json({ error: "Failed to delete category" });
  }
});

// --------------categories---------------
// --------------cart---------------
// add cart
app.post("/api/cart/add", requireLogin, async (req, res)=> {
  try {
    const { email, productID, quantities = 1, customValue = "" } = req.body;
    const existing = await pool.query(
      `SELECT * FROM main_customercart WHERE email_id=$1 AND product_id=$2 AND "customValue"=$3`,
      [email, productID, customValue]
    );

    if (existing.rows.length > 0) {
      await pool.query(
        `UPDATE main_customercart 
         SET quantities = quantities + $1 
         WHERE email_id=$2 AND product_id=$3 AND "customValue"=$4`,
        [quantities, email, productID, customValue]
      );
    } else {
      await pool.query(
        `INSERT INTO main_customercart (email_id, product_id, quantities, "customValue")
         VALUES ($1, $2, $3, $4)`,
        [email, productID, quantities, customValue]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add to cart" });
  }
});

// cart list for user
app.get("/api/cart/:email", requireLogin, async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query(
      `SELECT cc.*, p."productName", p.price, pi."imgURL"
       FROM main_customercart cc
       LEFT JOIN main_productdetail p ON cc.product_id = p."productID"
       LEFT JOIN LATERAL (
         SELECT "imgURL"
         FROM main_productimage
         WHERE product_id = p."productID"
         LIMIT 1
       ) pi ON true
       WHERE cc.email_id = $1`,
      [email]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch cart" });
  }
});

// Update cart
app.post("/api/cart/update", requireLogin, async (req, res) => {
  try {
    const { email, productID, customValue = "", quantities } = req.body;

    let query: string;
    let params: any[];

    if (customValue) {
      // custom product
      query = `
        UPDATE main_customercart
        SET quantities = $1
        WHERE email_id=$2 AND custom_product_id=$3 AND "customValue"=$4
      `;
      params = [quantities, email, productID, customValue];
    } else {
      // normal product
      query = `
        UPDATE main_customercart
        SET quantities = $1
        WHERE email_id = $2 AND product_id = $3 AND ("customValue" IS NULL OR "customValue" = '')
      `;
      params = [quantities, email, productID];
    }

    await pool.query(query, params);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to update cart" });
  }
});


// Remove from cart
app.post("/api/cart/remove", requireLogin, async (req, res) => {
  try {
    const { email, productID, customValue = "" } = req.body;

    let query: string;
    let params: any[];

    if (customValue) {
      // custom product
      query = `
        DELETE FROM main_customercart
        WHERE email_id=$1 AND custom_product_id=$2 AND "customValue"=$3
      `;
      params = [email, productID, customValue];
    } else {
      // normal product
      query = `
        DELETE FROM main_customercart
        WHERE email_id=$1 AND product_id=$2 AND ("customValue" IS NULL OR "customValue" = '')
      `;
      params = [email, productID];
    }

    await pool.query(query, params);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to remove from cart" });
  }
});


app.post("/api/cart/add-custom", uploadCustom.single("customImage"), requireLogin, async (req, res) => {
  try {
    const userEmail = req.session.user?.email; // <- from login session
    if (!userEmail) return res.status(401).json({ error: "Not logged in" });

    const { profile, keyColor, textColor, customText, notes } = req.body;
    const imagePath = req.file ? `/uploads/custom_products/${req.file.filename}` : "";
    const priceRes = await pool.query(
      `SELECT price FROM main_productdetail WHERE "productID"='KC_CUSTOM' LIMIT 1`
    );
    const customPrice = priceRes.rows[0]?.price ?? 0;

    const result = await pool.query(
      `INSERT INTO main_customproduct 
        (user_id, profile, "keyColor", "textColor", "customText", notes, "customImage", price)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id`,
      [userEmail, profile, keyColor, textColor, customText, notes, imagePath, customPrice]
    );

    const newCustomId = result.rows[0].id;

    await pool.query(
      `INSERT INTO main_customercart 
        (email_id, product_id, quantities, custom_product_id, "customValue")
       VALUES ($1, $2, $3, $4, $5)`,
      [userEmail, "KC_CUSTOM", 1, newCustomId, `${profile}_${keyColor}_${textColor}_${customText}`]
    );

    res.json({
      success: true,
      id: newCustomId,
      imagePath,
      price: customPrice,
      product_id: "KC_CUSTOM",
      customValue: `${profile}-${keyColor}-${textColor}-${customText}`,
    });
  } catch (err) {
    console.error("Error in /api/cart/add-custom:", err);
    res.status(500).json({ error: "Failed to create custom keycap" });
  }
});


// order
const query_orders = `
  SELECT 
    o.id,
    o.name,
    o.email_id,
    oi."productName",
    oi.quantities,
    o."orderStatus" ,
    o."orderDate"
  FROM main_order o
  LEFT JOIN main_orderitem oi ON o.id = oi.order_id
  ORDER BY o."orderDate" DESC
`;

app.get("/api/orders", async (req, res) => {
  try {
    const result = await pool.query(query_orders);
    res.json(result.rows);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Orders: Failed to fetch" });
  }
});

app.get("/api/orders/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `
        SELECT 
          o.id,
          o.name,
          o.email_id,
          o.phone,
          o.address,
          o."orderStatus",
          o."orderDate",
          json_agg(
            json_build_object(
              'productName', oi."productName",
              'quantities', oi.quantities,
              'custom_product_id', oi."custom_product_id",
              'product_id', oi."product_id",
              'customValue', oi."customValue"
            )
          ) AS items,
          p."totalPrice",
          p."transferSlip",
          p."paymentDate"
        FROM main_order o
        LEFT JOIN main_orderitem oi ON o.id = oi.order_id
        LEFT JOIN main_paymentdetail p ON o.id = p.order_id
        WHERE o.id = $1
        GROUP BY o.id, p."totalPrice", p."transferSlip", p."paymentDate"
      `,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to fetch this order" });
  }
});




app.put("/api/orders/:id", async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  if (!status) {
    return res.status(400).json({ error: "Status is required" });
  }

  try {
    const result = await pool.query(
      `UPDATE main_order
       SET "orderStatus" = $1
       WHERE id = $2
       RETURNING id, "orderStatus"`,
      [status, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json({ message: "Status updated", order: result.rows[0] });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ error: "Failed to update status" });
  }
});



// CREATE ORDER + ORDER ITEMS + CLEAR CART
app.post("/api/orders", requireLogin, async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    const {
      orderDate,
      orderStatus,
      totalPrice,
      name,
      phone,
      address,
      email_id,
      parcelStatus,
      items, // array of selected cart items
    } = req.body;

    if (!email_id) return res.status(401).json({ message: "Not logged in" });

    await client.query("BEGIN");

    // Insert order
    const orderResult = await client.query(
      `INSERT INTO main_order 
        ("orderDate", "orderStatus", "totalPrice", name, phone, address, email_id, "parcelStatus")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [orderDate, orderStatus, totalPrice, name, phone, address, email_id, parcelStatus]
    );

    const order = orderResult.rows[0];
    const orderId = order.id;

    // Insert order items
    if (items && items.length > 0) {
      for (const item of items) {
        const productId = item.product_id;
        const customProductId = item.custom_product_id || null;
        const optionId = item.option_id || null;

        await client.query(
          `INSERT INTO main_orderitem 
            ("customValue","quantities","eachTotalPrice","productName","order_id","product_id","option_id","custom_product_id")
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [
            item.customValue || "",
            item.quantities,
            item.price * item.quantities,
            item.productName,
            orderId,
            productId,
            optionId,
            customProductId,
          ]
        );
      }
    }

    // Delete checked items from main_customercart
    const cartIds = items
      .filter((i: any) => i.id) // ensure cart_id exists
      .map((i: any) => i.id);

    if (cartIds.length > 0) {
      await client.query(
        `DELETE FROM main_customercart WHERE id = ANY($1)`,
        [cartIds]
      );
    }

    await client.query("COMMIT");

    res.json(order);
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error creating order:", err);
    res.status(500).json({ error: "Failed to create order" });
  } finally {
    client.release();
  }
});


// UPLOAD PAYMENT DETAIL
app.post("/api/payment-details", requireLogin, upload.single("transferSlip"), async (req: Request, res: Response) => {
  try {
    const { totalPrice, paymentDate, order_id } = req.body;
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    if (!order_id) return res.status(400).json({ error: "order_id is required" });

    const filePath = `/uploads/slips/${req.file.filename}`;

    const result = await pool.query(
      `INSERT INTO main_paymentdetail ("totalPrice", "transferSlip", "paymentDate", order_id)
      VALUES ($1,$2,$3,$4) RETURNING *`,
      [totalPrice, filePath, paymentDate, Number(order_id)]
    );

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error saving payment detail:", err);
    res.status(500).json({ error: "Failed to save payment detail" });
  }
});


app.get("/api/orderhistory", requireLogin, async (req: Request, res: Response) => {
  try {
    const userEmail =
      typeof req.session.user === "string"
        ? req.session.user
        : req.session.user?.email;

    if (!userEmail) {
      return res.status(401).json({ message: "User not logged in" });
    }

    const query = `
      SELECT 
        o.id AS order_id,
        o."orderDate",
        o."orderStatus",
        o."totalPrice",
        o.name,
        o.phone,
        o.address,
        o.email_id,
        i.id AS orderitem_id,
        i."customValue",
        i."quantities",
        i."eachTotalPrice",
        i."productName",
        i."product_id",
        i."custom_product_id",
        COALESCE(i."custom_product_id"::text, i."product_id") AS final_product_id,
        img."imgURL"
      FROM main_order o
      LEFT JOIN main_orderitem i ON o.id = i."order_id"
      LEFT JOIN main_productimage img 
        ON img."product_id" = COALESCE(i."custom_product_id"::text, i."product_id")
      WHERE o."email_id" = $1
      ORDER BY o."orderDate" DESC;
    `;

    const result = await pool.query(query, [userEmail]);

    // Group by order
    const ordersMap: Record<string, any> = {};

    result.rows.forEach((row) => {
      if (!ordersMap[row.order_id]) {
        ordersMap[row.order_id] = {
          id: row.order_id,
          orderDate: row.orderDate,
          orderStatus: row.orderStatus,
          totalPrice: row.totalPrice,
          name: row.name,
          phone: row.phone,
          address: row.address,
          email_id: row.email_id,
          items: [],
        };
      }

      if (row.orderitem_id) {
        ordersMap[row.order_id].items.push({
          id: row.orderitem_id,
          productName: row.productName,
          quantities: row.quantities,
          eachTotalPrice: row.eachTotalPrice,
          imgURL: row.imgURL,
          product_id: row.final_product_id,
        });
      }
    });

    const orders = Object.values(ordersMap);
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/api/user/addresses", requireLogin, async (req, res) => {
  const sessionUser = req.session.user;

  // Ensure sessionUser is an object with email
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

  if (!userEmail) {
    return res.status(400).json({ error: "Email is required" });
  }

  try {
    const query = `
      SELECT 
        id, name, phone, province, district, subdistrict, postal_code, address, is_default
      FROM main_useraddress
      WHERE email_id = $1
      ORDER BY is_default DESC, id ASC
    `;
    const { rows } = await pool.query(query, [userEmail]);

    return res.json(rows);
  } catch (err) {
    console.error("Error fetching addresses:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/api/user/addresses/:id/default", requireLogin, async (req, res) => {
  const sessionUser = req.session.user;
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;
  const addrId = Number(req.params.id);

  if (!userEmail || !addrId) {
    return res.status(400).json({ error: "Email and Address ID are required" });
  }

  try {
    // Begin transaction
    await pool.query("BEGIN");

    // Reset all other addresses for this user
    await pool.query(
      `UPDATE main_useraddress
       SET is_default = FALSE
       WHERE email_id = $1`,
      [userEmail]
    );

    // Set this address as default
    await pool.query(
      `UPDATE main_useraddress
       SET is_default = TRUE
       WHERE id = $1 AND email_id = $2`,
      [addrId, userEmail]
    );

    await pool.query("COMMIT");

    return res.json({ success: true });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Error setting default address:", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get("/api/user/address", requireLogin, async (req, res) => {
  try {
  const sessionUser = req.session.user;
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

    if (!userEmail) {
      return res.status(400).json({ error: "Missing email" });
    }

    const query = `
      SELECT 
        name, 
        phone, 
        province, 
        district, 
        subdistrict, 
        postal_code, 
        address
      FROM main_useraddress 
      WHERE email_id = $1
    `;

    const result = await pool.query(query, [userEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Error fetching user address:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/user/addresses", requireLogin, async (req, res) => {
  try {
    const sessionUser = req.session.user;
    const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

    if (!userEmail) {
      return res.status(400).json({ error: "Email is required" });
    }

    const { name, phone, province, district, subdistrict, postal_code, address } = req.body;

    const query = `
      INSERT INTO main_useraddress
      (email_id, name, phone, province, district, subdistrict, postal_code, address, is_default)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false)
      RETURNING *
    `;

    const result = await pool.query(query, [
      userEmail,
      name,
      phone,
      province,
      district,
      subdistrict,
      postal_code,
      address,
    ]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Error creating address:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.delete("/api/user/addresses/:id", requireLogin, async (req, res) => {
  try {
    const sessionUser = req.session.user;
    const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;
    const addressId = req.params.id;

    if (!userEmail) return res.status(400).json({ error: "Email required" });

    const query = `
      DELETE FROM main_useraddress
      WHERE id = $1 AND email_id = $2
      RETURNING *
    `;

    const result = await pool.query(query, [addressId, userEmail]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Address not found" });
    }

    res.json({ message: "Address deleted successfully" });
  } catch (err) {
    console.error("Error deleting address:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/api/user/addresses/:id", requireLogin, async (req, res) => {
  const { id } = req.params;
  const sessionUser = req.session.user;
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

  if (!userEmail) return res.status(400).json({ error: "Missing email" });

  try {
    const query = `
      SELECT id, name, phone, province, district, subdistrict, postal_code, address, is_default
      FROM main_useraddress
      WHERE email_id = $1 AND id = $2
    `;
    const { rows } = await pool.query(query, [userEmail, id]);

    if (rows.length === 0) return res.status(404).json({ error: "Address not found" });

    res.json(rows[0]);
  } catch (err) {
    console.error("Error fetching address:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.put("/api/user/addresses/:id", requireLogin, async (req, res) => {
  const { id } = req.params;
  const { name, phone, province, district, subdistrict, postal_code, address } = req.body;
  const sessionUser = req.session.user;
  const userEmail = typeof sessionUser === "string" ? sessionUser : sessionUser?.email;

  if (!userEmail) return res.status(400).json({ error: "Missing email" });

  try {
    const query = `
      UPDATE main_useraddress
      SET name = $1, phone = $2, province = $3, district = $4, subdistrict = $5, postal_code = $6, address = $7
      WHERE email_id = $8 AND id = $9
      RETURNING *
    `;
    const { rows } = await pool.query(query, [name, phone, province, district, subdistrict, postal_code, address, userEmail, id]);

    res.json(rows[0]);
  } catch (err) {
    console.error("Error updating address:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 3001;

const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`;

app.listen(PORT, '0.0.0.0', () => console.log(`BackEnd: ${BACKEND_URL}/api/products`));

