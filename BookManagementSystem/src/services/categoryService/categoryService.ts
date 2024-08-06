import { inject, injectable } from 'inversify'
import { CategoryRepository } from '../../repositories/'
import { Category } from '../../interfaces/categoryInterface/categoryInterface'
import { PaginationService } from '../paginationService/paginationService'

@injectable()
export default class CategoryService {
  constructor(
    @inject(CategoryRepository) private categoryRepository: CategoryRepository,
    @inject(PaginationService) private paginationService: PaginationService
  ) {}

  async getAllCategories(
    page: number,
    limit: number
  ): Promise<{
    pagination: Category[]
    entriesFound: number
    page: number
    totalPages: number
  }> {
    const data = await this.categoryRepository.getAllCategories()
    const pagination = await this.paginationService.paginate(data, page, limit)
    const totalPages = await this.paginationService.getTotalPages(data, limit)
    const entriesFound = data.length
    return { pagination, entriesFound, page, totalPages }
  }

  async getCategoryList(
    searchQuery,
    categoryName,
    sortField,
    sortOrder,
    pageNumber,
    pageSize
  ) {
    const searchQueryOrDefault: string = searchQuery ? String(searchQuery) : '' // Default search query
    const categoryNameOrDefault: string = categoryName
      ? String(categoryName)
      : '' // Default category name
    const sortFieldOrDefault: string = sortField ? String(sortField) : 'name' // Default sort field
    const sortOrderOrDefault: string = sortOrder ? String(sortOrder) : 'asc' // Default sort order
    const pageNumberOrDefault: number = pageNumber
      ? parseInt(String(pageNumber), 10)
      : 1 // Default page number
    const pageSizeOrDefault: number = pageSize
      ? parseInt(String(pageSize), 10)
      : 10 // Default page size

    const data = await this.categoryRepository.getCategoryList(
      searchQueryOrDefault,
      categoryNameOrDefault,
      sortFieldOrDefault,
      sortOrderOrDefault,
      pageNumberOrDefault,
      pageSizeOrDefault
    )
    return data
  }

  async getCategoryById(id: string): Promise<Category> {
    return await this.categoryRepository.getCategoryById(id)
  }
  async createCategory(category: Category) {
    return await this.categoryRepository.createCategory(category)
  }
  async updateCategory(id: string, category: Category): Promise<Category> {
    const result = await this.categoryRepository.updateCategory(id, category)
    console.log('Result', result)
    if (result) {
      return result
    } else {
      throw new Error('Category not found')
    }
  }
  async deleteCategory(id: string) {
    return await this.categoryRepository.deleteCategory(id)
  }

  async searchCategories(keyword: string) {
    return await this.categoryRepository.searchCategories(keyword)
  }
}
