import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto, LoginDto, YouTubeDto, CodeDto, OAuthDto } from './user.dto';
import * as jwt from 'jsonwebtoken';
import { google } from 'googleapis';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private configService: ConfigService,
  ) {}

  async findByEmail(email: string) {
    try {
      const user = await this.userRepository.findOne({ where: { email } });
      if (!user) {
        throw new UnauthorizedException('Invalid credentials');
      }
      const { password, ...safeUser } = user;
      return { message: 'User found', success: true, ...safeUser };
    } catch (e) {
      return {
        message: e?.toString(),
        success: false,
      };
    }
  }

  async register(createUserDto: CreateUserDto) {
    try {
      const { name, email, password, method, username, creator } =
        createUserDto;

      if (!name || !email || !password || !username) {
        throw new BadRequestException('All fields are required.');
      }

      const existing = await this.userRepository.findOne({ where: { email } });
      if (existing) {
        throw new ConflictException('Email already registered');
      }
      const usernameExist = await this.userRepository.findOne({
        where: { username },
      });
      if (usernameExist) {
        throw new ConflictException('Username already registered');
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = this.userRepository.create({
        name: name,
        email: email,
        password: hashedPassword,
        method: method || 'normal',
        username: username,
        creator: creator || false,
      });
      await this.userRepository.save(newUser);
      return {
        message: 'Register successful',
        success: true,
        email,
        name,
      };
    } catch (e) {
      return {
        success: false,
        message: e?.toString(),
      };
    }
  }

  async login(loginDto: LoginDto) {
    try {
      const { email, password } = loginDto;
      if (!email || !password) {
        throw new BadRequestException('All fields are required.');
      }
      const userData = await this.userRepository.findOne({ where: { email } });
      const passwordMatch = await bcrypt.compare(password, userData?.password);
      if (!userData || !passwordMatch) {
        throw new UnauthorizedException('Invalid credentials');
      }
      const accessToken = jwt.sign(
        { name: userData.name, email: userData.email },
        process.env.JWT_SECRET!,
        { expiresIn: '1d' },
      );
      const refreshToken = crypto.randomUUID();
      const payload = {
        success: true,
        message: 'Login successful',
        userId: userData.id,
        name: userData.name,
        email: userData.email,
        accessToken,
        refreshToken,
      };
      return payload;
    } catch (e) {
      return { message: 'Invalid credentials', success: false };
    }
  }

  async getVideoStats(youtubeDto: YouTubeDto) {
    const youtube = google.youtube({
      version: 'v3',
      auth: this.configService.get<string>('YOUTUBE_API_KEY'),
    });

    const res = await youtube.videos.list({
      part: ['contentDetails,statistics'],
      id: [youtubeDto.videoId],
    });

    return res;
  }

  async loginViaGoogle() {
    const oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>('CLIENT_ID'),
      this.configService.get<string>('CLIENT_SECRET'),
      this.configService.get<string>('REDIRECT_URI'),
    );
    return oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/yt-analytics.readonly',
        'https://www.googleapis.com/auth/youtube.readonly',
      ],
    });
  }

  async handleCallback(codeDto: CodeDto) {
    const oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>('CLIENT_ID'),
      this.configService.get<string>('CLIENT_SECRET'),
      this.configService.get<string>('REDIRECT_URI')
    );
    const { tokens } = await oauth2Client.getToken(code); // exchange code for tokens
    oauth2Client.setCredentials(tokens);

    return tokens;
  }

  async getAnalytics(oauthDto: OAuthDto) {
    const youtubeAnalytics = google.youtubeAnalytics("v2");

    const response = await youtubeAnalytics.reports.query({
      auth: oauthDto.oauth2Client,
      ids: "channel==MINE",
      startDate: "2024-01-01",
      endDate: "2024-12-31",
      metrics: "views,estimatedMinutesWatched,estimatedRevenue",
      dimensions: "day",
      sort: "day",
    });

    return response.data;
  }
}
