// PaginationService.ts

import { inject, injectable } from 'inversify'
import PaginationRepository from '../../repositories/paginationRepository/paginationRepository'

@injectable()
export class PaginationService {
  constructor(
    @inject(PaginationRepository)
    private paginationRepository: PaginationRepository
  ) {}
  paginate<T>(data: T[], page: number, limit: number): T[] {
    return this.paginationRepository.paginate(data, page, limit)
  }

  getTotalPages<T>(data: T[], limit: number): number {
    return this.paginationRepository.getTotalPages(data, limit)
  }
}
