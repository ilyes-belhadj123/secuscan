"""Corpus de benchmark SecuScan — styles d'écriture courants dans les vrais projets (ne pas déployer)."""
from hashlib import md5


async def create_student(conn, name):
    async with conn.cursor() as cur:
        q = ("INSERT INTO students (name) "
             "VALUES ('%(name)s')" % {"name": name})
        await cur.execute(q)


async def find_students(conn, city):
    async with conn.cursor() as cur:
        q = ("SELECT id, name FROM students "
             "WHERE city = '{}'".format(city))
        await cur.execute(q)
        return await cur.fetchall()


async def find_students_safe(conn, city):
    async with conn.cursor() as cur:
        await cur.execute("SELECT id, name FROM students WHERE city = %(city)s", {"city": city})
        return await cur.fetchall()


def password_digest(password):
    return md5(password.encode()).hexdigest()
