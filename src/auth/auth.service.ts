import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from 'generated/prisma/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(dto: AuthDto) {
    //GENERATE THE PASSWORD HASH
    const hash = await argon.hash(dto.password);
    try {
      //SAVE THE NEW USER IN THE DB
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      //delete (user as any).hash;

      //RETURN THE SAVED USER
      return this.signToken(user.id, user.email);
    } catch (error) {
      if (
        error instanceof
        PrismaClientKnownRequestError
      ) {
        if (error.code === 'P2002') {
          throw new ForbiddenException(
            'Credentials Taken',
          );
        }
      }
      throw error;
    }
  }
  async signin(dto: AuthDto) {
    //FIND USER BY EMAIL
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });
    //IF USER DOES NOT EXIST THROW EXCEPTION
    if (!user) {
      throw new ForbiddenException(
        'Credentials Incorrect',
      );
    }

    //COMPARE PASSWORD
    const pwMatches = await argon.verify(
      user.hash,
      dto.password,
    );
    //IF PASSWORD INCORRECT THROW EXCEPTION
    if (!pwMatches) {
      throw new ForbiddenException(
        'Credentials Incorrect',
      );
    }

    //delete (user as any).hash;
    //SEND BACK USER
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret: secret,
      },
    );

    return {
      access_token: token,
    };
  }
}
