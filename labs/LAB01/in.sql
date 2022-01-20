create table foo(x blob(100));

INSERT into foo VALUES ('AAAA');
INSERT into foo VALUES ('BBBB');

SELECT * from foo;
