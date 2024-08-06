import { injectable, inject } from 'inversify'
import { AuthorRepository } from '../../repositories/authorRepository/authorRepository'
import { Author } from 'src/interfaces'
import { PaginationService } from '../paginationService/paginationService'
import CustomError from '../../helpers/customError'
import { errorCodes } from '../../constants'

@injectable()
export class AuthorService {
  constructor(
    @inject(AuthorRepository) private authorRepository: AuthorRepository,
    @inject(PaginationService) private paginationService: PaginationService
  ) {}
  public async getAuthors(query) {
    // console.log(query)
    const data = await this.authorRepository.getAuthors(query)
    return data
  }

  public async createAuthor(author: Author) {
    const result = await this.authorRepository.createAuthor(author)
    if (!result) {
      throw new CustomError(
        "Didn't Create Author Invalid Details",
        errorCodes.BAD_REQUEST,
        'InvalidDetails'
      )
    }
    return result
  }

  async updateAuthor(id: string, author: Author): Promise<Author> {
    const result = await this.authorRepository.updateAuthor(id, author)
    console.log('Result', result)
    if (result) {
      return result
    } else {
      throw new CustomError(
        'Author not found',
        errorCodes.NOT_FOUND,
        'NotFound'
      )
    }
  }
  async deleteAuthor(id: string) {
    return await this.authorRepository.deleteAuthor(id)
  }
}
