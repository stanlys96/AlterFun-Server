import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UsersService } from './user.service';
import { Body, Controller, Get, HttpStatus, Post, Query } from '@nestjs/common';
import { CreateUserDto, LoginDto } from './user.dto';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'Get a user' })
  @Get('user')
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Returns the specified user',
  })
  getUser(@Query('email') email: string): any {
    return this.usersService.findByEmail(email);
  }

  @ApiOperation({ summary: 'Register user by email' })
  @Post('register')
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Returns the reference id and email of the user registered',
  })
  registerUser(@Body() body: CreateUserDto): any {
    return this.usersService.register(body);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.usersService.login(loginDto);
  }
}
