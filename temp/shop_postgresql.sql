BEGIN;

CREATE TABLE IF NOT EXISTS userInfo (
    email TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    name TEXT,
    phone TEXT,
    gender TEXT,
    dob DATE,
    password TEXT
);

CREATE TABLE IF NOT EXISTS productCategory (
    categoryID SERIAL PRIMARY KEY,
    categoryName TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subCategory (
    categoryID INT NOT NULL,
    subID INT NOT NULL,
    subName TEXT NOT NULL,
    CONSTRAINT mainSubID PRIMARY KEY (categoryID, subID),
    FOREIGN KEY (categoryID) REFERENCES productCategory(categoryID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS productList (
    productID TEXT PRIMARY KEY,
    productName TEXT NOT NULL,
    categoryID INT NOT NULL,
    brand TEXT,
    price NUMERIC(10,2) NOT NULL,
    favoritesCount INT NOT NULL DEFAULT 0,
    addedDate TIMESTAMP,
    subID INT NOT NULL,
    description TEXT,
    FOREIGN KEY (categoryID, subID) REFERENCES subCategory(categoryID, subID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favoriteList (
    productID TEXT NOT NULL,
    email TEXT NOT NULL,
    PRIMARY KEY (productID, email),
    FOREIGN KEY (email) REFERENCES userInfo(email) ON DELETE CASCADE,
    FOREIGN KEY (productID) REFERENCES productList(productID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS customerCart (
    productID TEXT NOT NULL,
    email TEXT NOT NULL,
    quantities INT NOT NULL CHECK (quantities > 0),
    customValue TEXT,
    PRIMARY KEY (email, productID, customValue),
    FOREIGN KEY (email) REFERENCES userInfo(email) ON DELETE CASCADE,
    FOREIGN KEY (productID) REFERENCES productList(productID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "order" (
    orderId SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    orderDate TIMESTAMP NOT NULL,
    orderStatus TEXT NOT NULL,
    totalPrice NUMERIC(10,2) NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    FOREIGN KEY (email) REFERENCES userInfo(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS productOption (
    optionID SERIAL PRIMARY KEY,
    optionType TEXT NOT NULL,
    optionName TEXT NOT NULL,
    addPrice NUMERIC(10,2) NOT NULL DEFAULT 0,
    productID TEXT NOT NULL,
    imgURL TEXT,
    recommendedSize TEXT,
    FOREIGN KEY (productID) REFERENCES productList(productID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS orderItem (
    orderItemID SERIAL PRIMARY KEY,
    orderID INT NOT NULL,
    optionID INT,
    productID TEXT NOT NULL,
    customValue TEXT,
    quantities INT NOT NULL CHECK (quantities > 0),
    eachTotalPrice NUMERIC(10,2) NOT NULL,
    productName TEXT,
    FOREIGN KEY (orderID) REFERENCES "order"(orderId) ON DELETE CASCADE,
    FOREIGN KEY (optionID) REFERENCES productOption(optionID) ON DELETE SET NULL,
    FOREIGN KEY (productID) REFERENCES productList(productID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS optionCustom (
    customID SERIAL PRIMARY KEY,
    orderItemID INT NOT NULL,
    optionID INT,
    remark TEXT,
    attachedIMG TEXT,
    FOREIGN KEY (orderItemID) REFERENCES orderItem(orderItemID) ON DELETE CASCADE,
    FOREIGN KEY (optionID) REFERENCES productOption(optionID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS providerEditHistory (
    editID SERIAL PRIMARY KEY,
    modifiedTimestamp TIMESTAMP NOT NULL,
    productID TEXT NOT NULL,
    email TEXT NOT NULL,
    modifiedType TEXT,
    productDelName TEXT
);

CREATE TABLE IF NOT EXISTS providerList (
    email TEXT PRIMARY KEY,
    FOREIGN KEY (email) REFERENCES userInfo(email) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS userAddress (
    addressID SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    FOREIGN KEY (email) REFERENCES userInfo(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS productImage (
    productID TEXT NOT NULL,
    imgURL TEXT NOT NULL,
    FOREIGN KEY (productID) REFERENCES productList(productID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS paymentDetail (
    paymentID SERIAL PRIMARY KEY,
    orderID INT,
    totalPrice NUMERIC(10,2) NOT NULL DEFAULT 0,
    transferSlip TEXT,
    paymentDate TIMESTAMP NOT NULL
);

COMMIT;

-- generate this to django models.py, no need to add primary key. Also adjust the productList, productCategory and subCategory relationship. I want category-subCategory to be 1-to-many and productList-subCategory to be many-to-many.
-- productList change name to productDetail, remove favoritesCount, add size (text null) and material (text null)