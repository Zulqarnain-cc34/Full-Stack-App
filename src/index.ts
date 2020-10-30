import { PostResolver } from "./resolvers/Post";
import { MikroORM } from "@mikro-orm/core";
import { __prod__ } from "./constants";
//import { Post } from "./entities/Post";
import MikroConfig from "./mikro-orm.config";
import express from "express";
import { ApolloServer } from "apollo-server-express";
import { buildSchema } from "type-graphql";
import { UserResolver } from "./resolvers/User";
import "reflect-metadata";
import redis from "redis";
import session from "express-session";
import connectRedis from "connect-redis";

const main = async () => {
  const orm = await MikroORM.init(MikroConfig);
  await orm.getMigrator().up();
  //App
  const app = express();
  //const redisPort = 6379;

  //*Redis Connection initialization and setup of configuration
  //*intialization of connection,creating redis client and setting up of store
  const RedisStore = connectRedis(session);
  const redisClient = redis.createClient();

  //using redis in application and starting a session
  app.use(
    session({
      name: "qid",
      store: new RedisStore({ client: redisClient, disableTouch: true }),
      cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 365 * 10, //10 years
        httpOnly: true,
        sameSite: "lax", //csrf
        secure: !__prod__, //only works in https
      },
      saveUninitialized: false,
      secret: "sdafosfoasjkflsdjfafa90eolsd",
      resave: false,
    })
  );

  //Apollo connection and intialization of configuration
  const apolloServer = new ApolloServer({
    schema: await buildSchema({
      resolvers: [UserResolver, PostResolver],
      validate: false,
    }),
    context: ({ req, res }) => ({ em: orm.em, req, res }),
  });
  apolloServer.applyMiddleware({ app });

  app.listen(4000, () => {
    console.log("server started on port 4000");
  });
};

main().catch((err) => console.log(err));
