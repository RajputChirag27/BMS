import { BookController } from 'src/controllers'
import { ValidatorMiddleWare } from 'src/middlewares'
import { AuthorRepository, BookRepository } from 'src/repositories'
import { BookService } from 'src/services'

const TYPES = {
  // Controllers
  UserController: Symbol.for('UserController'),
  CategoryController: Symbol.for('CategoryController'),
  AuthorController: Symbol.for('AuthorController'),
  BookController: Symbol.for('BookController'),

  // Services
  UserService: Symbol.for('UserService'),
  CategoryService: Symbol.for('CategoryService'),
  AuthorService: Symbol.for('AuthorService'),
  BookService: Symbol.for('BookService'),

  // Middlewares
  AuthMiddleware: Symbol.for('AuthMiddleware'),
  isAdmin: Symbol.for('isAdmin'),
  ValidatorMiddleWare: Symbol.for('ValidatoryMiddleware'),

  // Validators
  UserValidator: Symbol.for('UserValidator'),
  CategoryValidator: Symbol.for('CategoryValidator'),

  // Repositories
  UserRepository: Symbol.for('UserRepository'),
  CategoryRepository: Symbol.for('CategoryRepository'),
  AuthorRepository: Symbol.for('AuthorRepository'),
  BookRepository: Symbol.for('BookRepository'),
}

export { TYPES }
