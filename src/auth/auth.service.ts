import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from 'src/prisma/prisma.service';
import { v4 as uuidv4 } from 'uuid';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpDto } from './dto/sign-up.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async signUp(signUpData: SignUpDto) {
    const { name, email, password } = signUpData;
    const usedEmail = await this.prisma.user.findUnique({
      where: { email },
    });

    if (usedEmail) {
      throw new BadRequestException('Email already is use');
    }

    const saltRound = 10;

    const passwordHash = await bcrypt.hash(password, saltRound);

    await this.prisma.user.create({
      data: {
        name,
        email,
        passwordHash,
      },
    });
  }

  async signIn(signInDto: SignInDto) {
    const { email, password } = signInDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const sessionId = uuidv4();
    const { accessToken, refreshToken } = await this.generateToken(sessionId);

    await this.storeRefreshToken(sessionId, refreshToken, user.id);

    return {
      accessToken,
      refreshToken,
    };
  }

  async generateToken(sessionId: string) {
    const accessToken = this.jwtService.sign(
      { sessionId },
      { expiresIn: '1h' },
    );
    const refreshToken = uuidv4();

    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(sessionId: string, token: string, userId: string) {
    // 3 Days
    const expiresIn = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000);
    await this.prisma.session.create({
      data: {
        sessionId,
        token,
        userId,
        expiresIn,
      },
    });
  }

  async refreshAccessToken(refreshToken: string) {
    const session = await this.prisma.session.findUnique({
      where: { token: refreshToken },
    });

    if (!session || !session.isActive) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const now = new Date();
    if (session.expiresIn < now) {
      throw new UnauthorizedException('Refresh token has expired');
    }

    const newAccessToken = this.jwtService.sign(
      { sessionId: session.sessionId },
      { expiresIn: '1h' },
    );

    return {
      accessToken: newAccessToken,
    };
  }

  async signOut(refreshToken: string) {
    const session = await this.prisma.session.findUnique({
      where: { token: refreshToken },
    });

    if (!session || !session.isActive) {
      throw new BadRequestException(
        'Session already signed out or does not exist',
      );
    }

    const updateSession = await this.prisma.session.update({
      where: { token: refreshToken },
      data: { isActive: false },
    });

    return !updateSession.isActive;
  }
}
