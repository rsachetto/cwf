PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "todolist_category" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(100) NOT NULL);
INSERT INTO todolist_category VALUES(1,'General');
INSERT INTO todolist_category VALUES(2,'Work');
INSERT INTO todolist_category VALUES(3,'Personal');
INSERT INTO todolist_category VALUES(4,'School');
INSERT INTO todolist_category VALUES(5,'Cleaning');
INSERT INTO todolist_category VALUES(6,'Other');
CREATE TABLE IF NOT EXISTS "todolist_todolist" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "title" varchar(250) NOT NULL, 
"content" text NOT NULL, "created" date NOT NULL, "category_id" integer NOT NULL REFERENCES "todolist_category" ("id"),
 "due_date" date NOT NULL);
INSERT INTO todolist_todolist VALUES(6,'Build a CWF todo list','Not used','2020-08-27',2,'2020-08-29');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('todolist_category',6);
INSERT INTO sqlite_sequence VALUES('todolist_todolist',8);
CREATE INDEX "todolist_todolist_category_id_da94bc90" ON "todolist_todolist" ("category_id");
COMMIT;
