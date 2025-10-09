import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { CREATE_FILE_QUEUE } from 'src/utils/constants';
import { axiosElwyn } from 'src/utils/axios';
import { UploadFileDTO } from './files.dto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as FormData from 'form-data';

interface FilesJobResult {
  jobStatus: string;
  message: string;
  processedId: string;
}

@Processor(CREATE_FILE_QUEUE)
export class CreateFileProcessor extends WorkerHost {
  async process(
    job: Job<UploadFileDTO, FilesJobResult, string>,
  ): Promise<FilesJobResult> {
    const { id, data } = job;
    const { fileName: filename, path: filePath } = data;
    let fileBuffer: Buffer | null = null;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30 * 1000);
      await job.updateProgress(10);
      try {
        const absolutePath = path.resolve(filePath);
        fileBuffer = await fs.readFile(absolutePath);
        const formData = new FormData();
        formData.append('file', fileBuffer, {
          filename: job.data.originalName,
          contentType: job.data.mimeType || 'application/octet-stream',
        });
        formData.append('organization_id', job.data.organization_id);
        const response = await axiosElwyn.post(
          '/assessment/upload-file',
          formData,
          {
            signal: controller.signal,
          },
        );

        const apiResponse: FilesJobResult = {
          jobStatus: 'success',
          message: 'Data processed successfully by external service!',
          processedId: `proc-${id}-${Date.now()}`,
          ...response.data,
        };

        await job.updateProgress(100);
        return apiResponse;
      } catch (e) {
        throw new Error(
          `External API Service Error for job ${id}: ${e?.message}`,
        );
      } finally {
        clearTimeout(timeout);
      }
    } catch (error) {
      console.error(
        `[Worker] Error during long API call for job ${id}:`,
        error.message,
      );
      throw new Error(
        `External API Service Error for job ${id}: ${error.message}`,
      );
    }
  }

  @OnWorkerEvent('completed')
  onCompleted(job: Job) {
    console.log(
      `[Worker Event] Job ${job.id} completed. Result:`,
      job.returnvalue,
    );
  }

  @OnWorkerEvent('failed')
  onFailed(job: Job, err: Error) {
    console.error(`[Worker Event] Job ${job.id} failed. Error:`, err.message);
  }

  @OnWorkerEvent('error')
  onError(err: Error) {
    console.error('[Worker Event] Worker-level error:', err);
  }
}
