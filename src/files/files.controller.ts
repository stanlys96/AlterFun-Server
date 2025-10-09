import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  HttpStatus,
  UseInterceptors,
  UploadedFile,
  Delete,
} from '@nestjs/common';
import { FilesService } from './files.service';
import { Job, Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import { CREATE_FILE_QUEUE, DELETE_FILE_QUEUE } from 'src/utils/constants';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { extname } from 'path';
import { UploadFileBodyDTO } from './files.dto';

@Controller('files')
export class FilesController {
  constructor(
    private readonly filesService: FilesService,
    @InjectQueue(CREATE_FILE_QUEUE)
    private readonly createFilesQueue: Queue,
    @InjectQueue(DELETE_FILE_QUEUE)
    private readonly deleteFileQueue: Queue,
  ) {}

  @Get('all/:principal')
  async getAllFiles(@Param('principal') principal: string) {
    return await this.filesService.getAllFiles(principal);
  }

  @Post('create')
  @UseInterceptors(
    FileInterceptor('file', {
      storage: diskStorage({
        destination: './uploads',
        filename: (req, file, callback) => {
          const uniqueSuffix =
            Date.now() + '-' + Math.round(Math.random() * 1e9);
          const ext = extname(file.originalname);
          callback(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
        },
      }),
      fileFilter: (req, file, callback) => {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif|pdf)$/)) {
          return callback(
            new Error('Only image and PDF files are allowed!'),
            false,
          );
        }
        callback(null, true);
      },
      limits: {
        fileSize: 1024 * 1024 * 5, // 5 MB limit
      },
    }),
  )
  async createFiles(
    @UploadedFile() file: Express.Multer.File,
    @Body() body: UploadFileBodyDTO,
  ) {
    const jobId = await this.filesService.performCreateFiles(
      file,
      body.organization_id,
    );
    return {
      statusCode: HttpStatus.ACCEPTED,
      message: 'Job enqueued successfully.',
      jobId: jobId,
    };
  }

  @Get('job-status-create/:jobId')
  async getCreateJobStatus(@Param('jobId') jobId: string) {
    const job: Job | undefined = await this.createFilesQueue.getJob(jobId);
    if (!job) {
      return {
        statusCode: HttpStatus.NOT_FOUND,
        message: 'Job not found.',
      };
    }

    const state = await job.getState();
    const progress = job.progress;
    let result = null;
    let failedReason: any = null;

    if (state === 'completed') {
      result = job.returnvalue;
    } else if (state === 'failed') {
      failedReason = job.failedReason;
    }

    return {
      statusCode: HttpStatus.OK,
      jobId: job.id,
      jobStatus: state,
      progress: progress,
      result: result,
      failedReason: failedReason,
    };
  }

  @Delete('file/:fileId')
  async deleteFile(@Param('fileId') fileId: string) {
    const jobId = await this.filesService.performDeleteFile(fileId);
    return {
      statusCode: HttpStatus.ACCEPTED,
      message: 'Job enqueued successfully.',
      jobId: jobId,
    };
  }

  @Get('job-status-delete/:jobId')
  async getDeleteJobStatus(@Param('jobId') jobId: string) {
    const job: Job | undefined = await this.deleteFileQueue.getJob(jobId);
    if (!job) {
      return {
        statusCode: HttpStatus.NOT_FOUND,
        message: 'Job not found.',
      };
    }

    const state = await job.getState();
    const progress = job.progress;
    let result = null;
    let failedReason: any = null;

    if (state === 'completed') {
      result = job.returnvalue;
    } else if (state === 'failed') {
      failedReason = job.failedReason;
    }

    return {
      statusCode: HttpStatus.OK,
      jobId: job.id,
      jobStatus: state,
      progress: progress,
      result: result,
      failedReason: failedReason,
    };
  }
}
