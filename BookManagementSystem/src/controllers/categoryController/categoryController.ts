import { NextFunction, Request, Response } from 'express'
import { inject } from 'inversify'
import {
  controller,
  httpDelete,
  httpGet,
  httpPatch,
  httpPost,
  request,
  response,
  next,
} from 'inversify-express-utils'
import { CategoryService } from '../../services'
import { Category } from '../../interfaces'
import { errorCodes } from '../../constants'
import {
  IsAdminMiddleware,
  JwtAuthenticationMiddleware,
  ValidatorMiddleWare,
} from '../../middlewares'
import { customErrorHandler } from '../../handler'

@controller('/category', JwtAuthenticationMiddleware, IsAdminMiddleware)
export class CategoryController {
  constructor(
    @inject(CategoryService) private readonly categoryService: CategoryService
  ) {}

  @httpGet('/')
  async getCategoryList(req: Request, res: Response): Promise<Response> {
    try {
      const {
        searchQuery,
        categoryName,
        sortField,
        sortOrder,
        pageNumber,
        pageSize,
      } = req.query

      // Provide default values for missing parameters

      // Call the service method with provided or default values
      const result = await this.categoryService.getCategoryList(
        searchQuery,
        categoryName,
        sortField,
        sortOrder,
        pageNumber,
        pageSize
      )

      return res.json(result)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpGet('/getAllCategories')
  async getAllCategories(req: Request, res: Response): Promise<void> {
    try {
      const page: number = parseInt(req.query.page as string) || 1
      const limit: number = parseInt(req.query.limit as string) || 10
      const categories = await this.categoryService.getAllCategories(
        page,
        limit
      )
      res.status(errorCodes.OK).json(categories)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpGet('/getCategoryById')
  async getCategoryById(req: Request, res: Response): Promise<void> {
    const categoryId = req.body.id
    try {
      const category = await this.categoryService.getCategoryById(categoryId)
      if (!category) {
        res.status(errorCodes.NOT_FOUND).json({ error: 'Category not found' })
        return
      }
      res.status(errorCodes.OK).json(category)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpPost('/', ValidatorMiddleWare)
  async createCategory(
    @request() req: Request,
    @response() res: Response,
    @next() next: NextFunction
  ): Promise<void> {
    const newCategory: Category = req.body
    try {
      const category = await this.categoryService.createCategory(newCategory)
      res.status(errorCodes.CREATED).json(category)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpPatch('/updateCategory/:id')
  async updateCategory(req: Request, res: Response): Promise<void> {
    const id = req.params.id
    const name = req.body.name
    console.log(id, name)
    try {
      const category: Category = await this.categoryService.updateCategory(
        id,
        name
      )
      console.log(category)
      if (!category) {
        res.status(errorCodes.NOT_FOUND).json({ error: 'Category not found' })
        return
      }
      res.status(errorCodes.OK).json(category)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpDelete('/deleteCategory/:id')
  async deleteCategory(req: Request, res: Response): Promise<void> {
    const categoryId = req.params.id
    try {
      const deleted = await this.categoryService.deleteCategory(categoryId)
      if (deleted === null) {
        const err = {
          name: 'CategoryNotFoundError',
        }
        customErrorHandler(err, req, res, next)
        return
      } else {
        res.send({ deleted, message: 'Deleted Successfully' })
      }
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }

  @httpGet('/searchCategories')
  async searchCategories(req: Request, res: Response): Promise<void> {
    const keyword = req.body.search
    try {
      const categories = await this.categoryService.searchCategories(keyword)
      res.status(errorCodes.OK).json(categories)
    } catch (error) {
      customErrorHandler(error, req, res, next)
    }
  }
}
