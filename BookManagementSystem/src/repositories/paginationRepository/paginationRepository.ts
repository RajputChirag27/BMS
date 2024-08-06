import { injectable } from 'inversify'
import { Category } from '../../interfaces'
import { CategoryModel } from '../../models'

@injectable()
export default class PaginationRepository {
  paginate<T>(data: T[], page: number, limit: number): T[] {
    const startIndex = (page - 1) * limit
    const endIndex = page * limit
    data = data.slice(startIndex, endIndex)
    return data
  }

  getTotalPages<T>(data: T[], limit: number): number {
    return Math.ceil(data.length / limit)
  }
}
