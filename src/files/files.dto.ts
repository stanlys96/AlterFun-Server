export interface UploadFileDTO {
  message: string;
  fileName: string;
  originalName: string;
  size: number;
  mimeType: string;
  path: string;
  organization_id?: string;
}

export interface UploadFileBodyDTO {
  organization_id?: string;
}

export interface DeleteFileDTO {
  fileId: string;
}
