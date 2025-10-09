import { BullModule } from '@nestjs/bullmq';
import { Module } from '@nestjs/common';
import { FilesController } from './files.controller';
import { CreateFileProcessor } from './create-files.processor';
import { CREATE_FILE_QUEUE, DELETE_FILE_QUEUE } from 'src/utils/constants';
import { FilesService } from './files.service';
import { DeleteFileProcessor } from './delete-file.processor';

@Module({
  imports: [
    BullModule.registerQueue({
      name: CREATE_FILE_QUEUE,
    }),
    BullModule.registerQueue({
      name: DELETE_FILE_QUEUE,
    }),
  ],
  controllers: [FilesController],
  providers: [CreateFileProcessor, FilesService, DeleteFileProcessor],
})
export class FilesModule {}
