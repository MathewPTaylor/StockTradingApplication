CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
    username TEXT NOT NULL, 
    hash TEXT NOT NULL, 
    cash NUMERIC NOT NULL DEFAULT 10000.00
);
-- CREATE TABLE sqlite_sequence(name,seq);
CREATE UNIQUE INDEX username ON users (username);
CREATE TABLE ownerships (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, 
    user_id INTEGER NOT NULL, 
    symbol VARCHAR(20) NOT NULL, 
    shares INTEGER NOT NULL, 
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    symbol VARCHAR(20) NOT NULL,
    shares INTEGER NOT NULL,
    price FLOAT NOT NULL,
    transaction_datetime TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);