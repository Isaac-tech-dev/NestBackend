import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import {
  ExtractJwt,
  Strategy,
} from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(
  Strategy,
) {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest:
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey:
        config.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: any) {
    // Whatever you return here will be attached to req.user
    return payload;
  }
}
