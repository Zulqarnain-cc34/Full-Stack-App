import { User } from "../entities/User";
import {
  Arg,
  Ctx,
  Field,
  Mutation,
  ObjectType,
  Query,
  Resolver,
} from "type-graphql";
import { MyContext } from "src/types";
import argon2 from "argon2";

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;

  @Field(() => Boolean, { nullable: true })
  logout?: boolean;
}
@ObjectType()
class FieldError {
  @Field()
  field: string;
  @Field()
  message: string;
}
@Resolver()
export class UserResolver {
  @Query(() => [User])
  Users(@Ctx() { em }: MyContext): Promise<User[]> {
    return em.find(User, {});
  }

  @Query(() => User, { nullable: true })
  async me(@Ctx() { req, em }: MyContext): Promise<User | null> {
    if (!req.session.userId) {
      return null;
    }
    const user = await em.findOne(User, { id: req.session.userId });
    return user;
  }

  @Mutation(() => UserResponse)
  async register(
    @Arg("username") username: string,
    @Arg("password") password: string,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    if (username.length <= 2) {
      return {
        errors: [
          {
            field: "username",
            message: "username length too short it is not possible",
          },
        ],
      };
    }
    if (password.length <= 2) {
      return {
        errors: [
          {
            field: "password",
            message: "password length must be atleast 2 characers long",
          },
        ],
      };
    }
    const HashedPassword = await argon2.hash(password);
    const user = await em.create(User, {
      username: username,
      password: HashedPassword,
    });
    try {
      await em.persistAndFlush(user);
    } catch (err) {
      if (err.code === "23505") {
        return {
          errors: [{ field: "username", message: "Username is already taken" }],
        };
      }
      console.log("message: ", err);
    }
    //This will sutologin the user when registering
    req.session.userId = user.id;
    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("username") username: string,
    @Arg("password") password: string,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    console.log(req.session);
    //const HashedPassword = await argon2.hash(password);
    const user = await em.findOne(User, {
      username: username,
    });

    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "the username doesnot exist",
          },
        ],
      };
    }
    const valid = await argon2.verify(user.password, password);

    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "incorrect password",
          },
        ],
      };
    }
    req.session.userId = user.id;

    return {
      user,
    };
  }

  @Mutation(() => UserResponse)
  async logout(@Ctx() { em, req }: MyContext): Promise<UserResponse> {
    const user = await em.findOne(User, {
      id: req.session.userId,
    });
    if (!user) {
      return {
        errors: [
          {
            field: "user",
            message: "You are already logged out",
          },
        ],
      };
    }

    req.session.userId = null;
    return {
      logout: true,
    };
  }

  @Mutation(() => User, { nullable: true })
  async ForgotPassword(
    @Arg("id") id: number,
    @Arg("username", () => String, { nullable: true }) username: string,
    @Ctx() { em }: MyContext
  ): Promise<User | null> {
    const user = await em.findOne(User, { id });
    if (!user) {
      return null;
    }
    if (username) {
      user.username = username;
    }
    return user;
  }

  //@Mutation(() => Boolean)
  //async deleteUser(
  //  @Arg("id") id: number,
  //  @Ctx() { em }: MyContext
  //): Promise<boolean> {
  //  await em.nativeDelete(User, { id });
  //  return true;
  //}
}
