import { NextFunction, Request, Response } from 'express'
import { inject } from 'inversify'
import {
  controller,
  httpGet,
  httpPost,
  httpDelete,
  httpPatch,
} from 'inversify-express-utils'
import { BookService } from '../../services'
import { AuthenticatedRequest, Book } from '../../interfaces'
import {
  IsAdminMiddleware,
  JwtAuthenticationMiddleware,
  ValidatorMiddleWare,
} from '../../middlewares'
import { errorCodes } from '../../constants'
import { customErrorHandler } from '../../handler'

@controller('/books')
export class BookController {
  constructor(@inject(BookService) private bookService: BookService) {}

  @httpPost(
    '/',
    JwtAuthenticationMiddleware,
    IsAdminMiddleware,
    ValidatorMiddleWare
  )
  async createBook(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      const bookData: Book = req.body
      const book = await this.bookService.createBook(bookData)
      res.status(errorCodes.OK).json(book)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet('/')
  async getBooks(req: Request, res: Response, next: NextFunction) {
    try {
      const queryObject = { ...req.query }
      const result = await this.bookService.getBooks(queryObject)
      res.status(result.statusCode).json(result.data)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpPatch('/:id', JwtAuthenticationMiddleware)
  async updateBook(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      const id: string = req.params.id
      const bookData: Book = req.body
      const updatedBook = await this.bookService.updateBook(id, bookData)
      if (!updatedBook) {
        res.status(errorCodes.NOT_FOUND).json({ message: 'Book not found' })
      } else {
        res.status(errorCodes.OK).json(updatedBook)
      }
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpDelete('/:id', JwtAuthenticationMiddleware)
  async deleteBook(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      const id: string = req.params.id
      const deletedBook = await this.bookService.deleteBook(id)
      if (!deletedBook) {
        res.status(errorCodes.NOT_FOUND).json({ message: 'Book not found' })
      } else {
        res.status(errorCodes.OK).json({ message: 'Book deleted successfully' })
      }
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet('/filter')
  async filterBooks(req: Request, res: Response, next: NextFunction) {
    try {
      const query = req.query.query || ''
      const minPrice: number = parseFloat(req.query.minPrice as string) || 0
      const maxPrice: number =
        parseFloat(req.query.maxPrice as string) || Number.POSITIVE_INFINITY
      if (query === '') {
        const book = await this.bookService.filterBooksByPrice(
          minPrice,
          maxPrice
        )
        res.send(book)
        return
      }
      const books = await this.bookService.filterBooks(
        query,
        minPrice,
        maxPrice
      )
      res.status(errorCodes.OK).json(books)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet('/search')
  async searchBooks(req: Request, res: Response, next: NextFunction) {
    try {
      const query: string = (req.query.q as string) || ''
      const books = await this.bookService.searchBooks(query)
      res.status(errorCodes.OK).json(books)
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }

  @httpGet('/:id', JwtAuthenticationMiddleware)
  async getBookById(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    try {
      const id: string = req.params.id
      const book = await this.bookService.getBookById(id)
      if (!book) {
        res.status(errorCodes.NOT_FOUND).json({ message: 'Book not found' })
      } else {
        res.status(errorCodes.OK).json(book)
      }
    } catch (err) {
      customErrorHandler(err, req, res, next)
    }
  }
}
