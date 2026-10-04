import {
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcryptjs';
import { Repository } from 'typeorm';
import { AuthToken } from '../database/entities/auth-token.entity';
import { User } from '../database/entities/user.entity';
import type { LoginDto, SetupSuperuserDto } from './auth.dto';
import {
  ALL_PERMISSIONS,
  normalizePermissions,
  Permission,
} from './permissions';

export interface AuthUserResponse {
  id: number;
  username: string;
  isSuperuser: boolean;
  permissions: Permission[];
  permissionLabels: Record<Permission, string>;
  canManageUsers: boolean;
  createdAt: Date;
}

export interface AuthResponse {
  accessToken: string;
  user: AuthUserResponse;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    @InjectRepository(AuthToken)
    private readonly authTokensRepository: Repository<AuthToken>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async needsSetup(): Promise<boolean> {
    const count = await this.usersRepository.count();
    return count === 0;
  }

  async createSuperuser(dto: SetupSuperuserDto): Promise<AuthResponse> {
    if (!(await this.needsSetup())) {
      throw new ConflictException('Superuser already exists');
    }

    const passwordHash = await bcrypt.hash(dto.password, 12);
    const user = this.usersRepository.create({
      username: dto.username,
      email: null,
      passwordHash,
      isSuperuser: true,
      permissions: ALL_PERMISSIONS,
      role: null,
    });

    const savedUser = await this.usersRepository.save(user);
    return this.issueAuthResponse(savedUser);
  }

  async login(dto: LoginDto): Promise<AuthResponse> {
    const user = await this.usersRepository.findOne({
      where: { username: dto.username },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid username or password');
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.passwordHash);

    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid username or password');
    }

    return this.issueAuthResponse(user);
  }

  async logout(token: string | undefined): Promise<{ success: true }> {
    if (!token) {
      return { success: true };
    }

    await this.authTokensRepository.delete({ token });
    return { success: true };
  }

  toUserResponse(user: User): AuthUserResponse {
    const permissions = normalizePermissions(user.permissions);

    return {
      id: user.id,
      username: user.username,
      isSuperuser: user.isSuperuser,
      permissions,
      permissionLabels: {
        [Permission.READ]: 'Чтение',
        [Permission.WRITE]: 'Запись',
        [Permission.ADMINISTRATION]: 'Администрирование',
      },
      canManageUsers: user.isSuperuser || permissions.includes(Permission.ADMINISTRATION),
      createdAt: user.createdAt,
    };
  }

  async getUserById(id: number): Promise<User> {
    const user = await this.usersRepository.findOne({ where: { id } });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  assertCanManageUsers(user: Pick<User, 'isSuperuser' | 'permissions'>): void {
    const permissions = normalizePermissions(user.permissions);

    if (!user.isSuperuser && !permissions.includes(Permission.ADMINISTRATION)) {
      throw new ForbiddenException('Administration permission required');
    }
  }

  private async issueAuthResponse(user: User): Promise<AuthResponse> {
    const expiresInDays = parseInt(
      this.configService.get<string>('JWT_EXPIRES_IN_DAYS', '7'),
      10,
    );
    const expiresAt = new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000);
    const payload = { sub: user.id, username: user.username };
    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: expiresInDays * 24 * 60 * 60,
    });

    await this.authTokensRepository.save(
      this.authTokensRepository.create({
        user,
        token: accessToken,
        type: 'access',
        expiresAt,
      }),
    );

    return {
      accessToken,
      user: this.toUserResponse(user),
    };
  }
}
