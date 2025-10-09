import { Processor, WorkerHost, OnWorkerEvent } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { DELETE_FILE_QUEUE } from 'src/utils/constants';
import { axiosElwyn } from 'src/utils/axios';
import { DeleteFileDTO } from './files.dto';

interface DeleteFileJobResult {
  jobStatus: string;
  message: string;
  processedId: string;
}

@Processor(DELETE_FILE_QUEUE)
export class DeleteFileProcessor extends WorkerHost {
  async process(
    job: Job<DeleteFileDTO, DeleteFileJobResult, string>,
  ): Promise<DeleteFileJobResult> {
    const { id, data } = job;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30 * 1000);
      await job.updateProgress(10);
      try {
        const response = await axiosElwyn.delete(
          `/conversational/files/${data.fileId}`,
          {
            data: {
              file_id: data.fileId,
            },
            signal: controller.signal,
          },
        );

        const apiResponse: DeleteFileJobResult = {
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
