import { inject, injectable } from 'inversify'
import { BookRepository } from '../../repositories'
import { Book } from '../../interfaces'
import { PaginationService } from '../paginationService/paginationService'

@injectable()
class BookService {
  constructor(
    @inject(BookRepository) private bookRepository: BookRepository,
    @inject(PaginationService) private paginationService: PaginationService
  ) {}

  async createBook(bookData: Book): Promise<Book> {
    return await this.bookRepository.createBook(bookData)
  }

  async getBooks(query) {
    const data = await this.bookRepository.getBooks(query)
    return data
  }

  // async getBooksViaPipeline(query){

  // }

  async getBookById(id: string): Promise<Book> {
    return await this.bookRepository.getBookById(id)
  }

  async updateBook(id: string, bookData: Book): Promise<Book> {
    return await this.bookRepository.updateBook(id, bookData)
  }

  async deleteBook(id: string) {
    return await this.bookRepository.deleteBook(id)
  }

  async searchBooks(query): Promise<Book[]> {
    return await this.bookRepository.searchBooks(query)
  }

  async filterBooks(
    query?,
    minPrice?: number,
    maxPrice?: number
  ): Promise<Book[]> {
    try {
      return await this.bookRepository.filterBooks(query, minPrice, maxPrice)
    } catch (error) {
      throw new Error('Could not filter books')
    }
  }

  async filterBooksByPrice(
    minPrice: number,
    maxPrice: number
  ): Promise<Book[]> {
    try {
      return await this.bookRepository.filterBooksByPrice(minPrice, maxPrice)
    } catch (error) {
      throw new Error('Could not filter books')
    }
  }
}

export default BookService
