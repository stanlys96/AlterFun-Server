import { Injectable } from '@nestjs/common';
import { Queue } from 'bullmq';
import { InjectQueue } from '@nestjs/bullmq';
import {
  CREATE_FILE_JOB,
  CREATE_FILE_QUEUE,
  DELETE_FILE_JOB,
  DELETE_FILE_QUEUE,
} from 'src/utils/constants';
import { DeleteFileDTO, UploadFileDTO } from './files.dto';
import { axiosElwyn } from 'src/utils/axios';

@Injectable()
export class FilesService {
  constructor(
    @InjectQueue(CREATE_FILE_QUEUE)
    private readonly createFileQueue: Queue<UploadFileDTO>,
    @InjectQueue(DELETE_FILE_QUEUE)
    private readonly deleteFileQueue: Queue<DeleteFileDTO>,
  ) {}

  async getAllFiles(principal: string) {
    const response = await axiosElwyn.get(
      `/conversational/files/organization?organization_id=${principal}`,
    );
    return response?.data;
  }

  async performCreateFiles(
    file: Express.Multer.File,
    organization_id?: string,
  ): Promise<string> {
    const job = await this.createFileQueue.add(
      CREATE_FILE_JOB,
      {
        message: 'File uploaded successfully',
        fileName: file.filename,
        originalName: file.originalname,
        size: file.size,
        mimeType: file.mimetype,
        path: file.path,
        organization_id: organization_id,
      },
      {
        attempts: 1,
        backoff: {
          type: 'exponential',
          delay: 5000,
        },
        removeOnComplete: false,
        removeOnFail: false,
      },
    );
    return job.id!;
  }

  async performDeleteFile(fileId: string): Promise<string> {
    const job = await this.deleteFileQueue.add(
      DELETE_FILE_JOB,
      {
        fileId: fileId,
      },
      {
        attempts: 1,
        backoff: {
          type: 'exponential',
          delay: 5000,
        },
        removeOnComplete: false,
        removeOnFail: false,
      },
    );
    return job.id!;
  }
}
