import { Context, Hono } from "hono";
import { basicAuth } from "hono/basic-auth";
import { cors } from "hono/cors";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { compare, hash } from "bcryptjs";

interface KVUser {
  id: string;
  username: string;
  passwordHash: string;
}

export interface Env {
  JWT_SECRET_KEY: string;
  ADMIN_USERNAME: string;
  ADMIN_PASSWORD: string;
  SALT_ROUNDS: number;
  USERS: KVNamespace;
  MOVIES: KVNamespace;
}

// Object that is stored in the JWT token
interface userToken {
  username: string;
  id: string;
}

// Object that is returned from the token validation
// decodedToken is only set if ok is true
interface tokenValidationStatus {
  ok: boolean;
  message: string;
  decodedToken?: userToken;
}

// Extracted from request body for login and signup
interface AuthBody {
  username: string;
  password: string;
}

const app = new Hono<{ Bindings: Env }>();

const tokenKey = (c: Context): string => {
  const key = c.env.JWT_SECRET_KEY ?? "DEV-SUPA-SEKIT";
  return key;
};

// https://hono.dev/docs/middleware/builtin/cors
app.use("*", cors());

// TODO: Add a middleware to check if the user is logged in
// TODO: Add a middleware to check the body is valid JSON and has `username` and `password`
app.post("/auth/login", async (c) => {
  const body = await parseAuthBody(c);
  if (!body) {
    return c.json({ ok: false, message: "Invalid JSON" }, 400);
  }
  const { username, password } = body;
  const userJson = await c.env.USERS.get(username);
  const user = userJson ? (JSON.parse(userJson) as KVUser) : null;
  if (user === null) {
    return c.json({ ok: false, message: "Login failed" }, 401);
  }
  const passwordCorrect = await compare(password, user.passwordHash);
  // const passwordHash = await generatePasswordHash(password);
  // const passwordCorrect = passwordHash === user.passwordHash;
  if (!passwordCorrect) {
    return c.json({ ok: false, message: "Login failed" }, 401);
  }

  const userForToken: userToken = {
    username: user.username,
    id: user.id,
  };

  const token = jwt.sign(userForToken, tokenKey(c));

  return c.json({
    token,
    username: user.username,
    status: 200,
  });
});

const generatePasswordHash = async (password: string, c: Context) => {
  // const hashAlgo = crypto.createHash("sha512");
  // hashAlgo.update(password);
  // const passwordHash = hashAlgo.digest("hex");
  // return passwordHash;
  return await hash(password, c.env.SALT_ROUNDS);
};

const generateToken = (username: string, id: string, c: Context) => {
  const userForToken: userToken = {
    username,
    id,
  };
  // Might need to use JSON.stringify(userForToken)
  const token = jwt.sign(userForToken, tokenKey(c));
  return token;
};

const verifyAndDecodeToken = (c: Context): tokenValidationStatus => {
  const authorization = c.req.raw.headers.get("Authorization");
  if (!authorization) {
    return {
      ok: false,
      message: "Authorization header missing",
    };
  }
  if (!authorization.startsWith("Bearer ")) {
    return {
      ok: false,
      message: "Authorization header invalid",
    };
  }
  let decodedToken;
  try {
    const token = authorization.slice(7);
    decodedToken = jwt.verify(token, tokenKey(c));
  } catch (error) {
    return {
      ok: false,
      message: "Token invalid",
    };
  }
  if (
    typeof decodedToken === "string" ||
    !decodedToken.id ||
    !decodedToken.username
  ) {
    return {
      ok: false,
      message: "Token invalid",
    };
  }
  return {
    ok: true,
    message: "Token valid",
    decodedToken: decodedToken as userToken,
  };
};

const parseBody = async (c: Context) => {
  let body;
  try {
    body = await c.req.json();
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error("Found error!", error.message);
    } else {
      console.error("Found unknown error!");
    }
    return null;
  }
  return body;
};

const parseAuthBody = async (c: Context): Promise<AuthBody | null> => {
  const authBody = await parseBody(c);
  if (!authBody) {
    return null;
  }
  const { username, password } = authBody;
  if (
    !username ||
    !password ||
    typeof username !== "string" ||
    typeof password !== "string"
  ) {
    return null;
  }
  return authBody as AuthBody;
};

app.post("/auth/signup", async (c) => {
  const body = await parseAuthBody(c);
  if (!body) {
    return c.json({ ok: false, message: "Invalid JSON" }, 400);
  }
  const { username, password } = body as AuthBody;
  if (!username || !password) {
    return c.json(
      { ok: false, message: "`username` and `password` required" },
      400
    );
  }
  const userJson = await c.env.USERS.get(username);
  const user = userJson ? (JSON.parse(userJson) as KVUser) : null;
  if (user) {
    return c.json({ ok: false, message: "User already exists" }, 400);
  }
  const passwordHash = await generatePasswordHash(password, c);
  const id = crypto.randomUUID();
  const userData: KVUser = { id, username, passwordHash };
  await c.env.USERS.put(username, JSON.stringify(userData));
  await c.env.MOVIES.put(username, JSON.stringify({}));
  const token = generateToken(username, id, c);
  return c.json({ ok: true, message: "User created", token }, 201);
});

app.get("/auth/test", async (c) => {
  const username = "foo";
  const password = "bar";
  const id = crypto.randomUUID();
  const passwordHash = await generatePasswordHash(password, c);
  const token = generateToken(username, id, c);
  return c.json({
    ok: true,
    message: "Token valid",
    id,
    username,
    password,
    passwordHash,
    token,
  });
});

app.get("/api/v1/movies", async (c) => {
  const decodedToken = verifyAndDecodeToken(c);
  if (!decodedToken.ok) {
    return c.json({ ok: false, message: decodedToken.message }, 401);
  }
  const username = decodedToken.decodedToken!.username;
  let movies = await c.env.MOVIES.get(username);
  if (!movies) {
    // Create a new KV namespace for the user
    await c.env.MOVIES.put(username, JSON.stringify({}));
    movies = JSON.stringify({});
  }
  return c.json(movies);
});

app.post("/api/v1/movies", async (c) => {
  const decodedToken = verifyAndDecodeToken(c);
  if (!decodedToken.ok) {
    return c.json({ ok: false, message: decodedToken.message }, 401);
  }
  const username = decodedToken.decodedToken!.username;
  const body = await parseBody(c);
  if (!body || !Array.isArray(body.movies)) {
    return c.json({ ok: false, message: "Invalid JSON" }, 400);
  }
  let { movies } = body;
  await c.env.MOVIES.put(username, JSON.stringify(movies));
  return c.json({ ok: true, message: "Movies created" }, 201);
});

app.get("/", (c) => {
  return c.text("Hello Hono!");
});

app.get("/api/v1/hello", (c) => {
  return c.json({
    ok: true,
    message: "Hello Hono!",
  });
});

app.get("/api/v1/posts/:id", (c) => {
  const page = c.req.query("page");
  const id = c.req.param("id");
  c.header("X-Message", "Hi!");
  return c.text(`You want to see page ${page} of ${id}`);
});

app.post("/api/v1/posts", (c) => c.text("Created!", 201));
app.delete("/posts/:id", (c) => c.text(`${c.req.param("id")} is deleted!`));

// const View = () => {
//   return (
//     <html>
//       <body>
//         <h1>Hello Hono!</h1>
//       </body>
//     </html>
//   );
// };
// app.get("/page", (c) => c.html(<View />));
app.get("/raw", () => {
  return new Response("Good morning!");
});

app.use("/admin/*", async (ctx: Context, next: any) => {
  const env = ctx.env;
  return basicAuth({
    username: env.ADMIN_USERNAME,
    password: env.ADMIN_PASSWORD,
  })(ctx, next);
});

app.get("/admin", (c) => {
  return c.text("You are authorized!");
});

app.delete("/admin/user/:username", async (c) => {
  const username = c.req.param("username");
  if (!username) {
    return c.json({ ok: false, message: "Username required" }, 400);
  }
  await c.env.USERS.delete(username);
  await c.env.MOVIES.delete(username);
  return c.json({ ok: true, message: "User deleted" }, 200);
});

export default app;
