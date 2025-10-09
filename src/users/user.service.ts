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
import { CreateUserDto, LoginDto } from './user.dto';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
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
      const { name, email, password, method } = createUserDto;

      if (!name || !email || !password) {
        throw new BadRequestException('All fields are required.');
      }

      const existing = await this.userRepository.findOne({ where: { email } });
      if (existing) {
        throw new ConflictException('Email already registered');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = this.userRepository.create({
        name: name,
        email: email,
        password: hashedPassword,
        method: method,
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
}
