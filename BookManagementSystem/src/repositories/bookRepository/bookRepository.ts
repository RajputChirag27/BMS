import { injectable } from 'inversify'
import { Book } from '../../interfaces'
import { BookModel, CategoryModel, AuthorModel } from '../../models'
import { errorCodes, errorMessages } from '../../constants'

@injectable()
export class BookRepository {
  async getBooks(queries) {
    try {
      let queryObject = { ...queries }

      // Basic Filteration

      const excludeFields = ['page', 'sort', 'limit', 'fields']
      excludeFields.forEach(item => delete queryObject[item])

      // Advance Filteration

      let queryString = JSON.stringify(queryObject)

      queryString = queryString.replace(
        /\b(gte|eq|gt|lte|lt)\b/g,
        match => `$${match}`
      )

      queryObject = JSON.parse(queryString)

      // Global Search
      if (queryObject.search) {
        const searchRegex = new RegExp(queryObject.search, 'i')
        delete queryObject.search
        queryObject.$or = [
          { title: searchRegex },
          { authorName: searchRegex },
          { categoryName: searchRegex },
          { ISBN: searchRegex },
          { description: searchRegex },
        ]
      }

      if (queryObject.name) {
        queryObject.name = new RegExp(queryObject.name, 'i')
      }

      let query = BookModel.find({ ...queryObject })
      const countQuery = BookModel.find({ ...queryObject })

      // Sorting
      if (queries.sort) {
        const sortBy = (queries.sort as string).split(',').join(' ')
        query = query.sort(sortBy)
      } else {
        query = query.sort({ createdAt: -1 })
      }

      // Projection
      if (queries.fields) {
        const fields = (queries.fields as string).split(',').join(' ')
        query = query.select(fields)
      } else {
        query = query.select('-__v')
      }

      // Pagination
      const page = parseInt(queries.page as string) || 1
      const limit = parseInt(queries.limit as string) || 10
      const skip = (page - 1) * limit

      const totalRecords = await countQuery.countDocuments()

      query = query.skip(skip).limit(limit)

      let numOfRecords = 0
      if (queries.page) {
        numOfRecords = await BookModel.countDocuments({ ...queryObject })
        if (skip > numOfRecords) {
          throw Object.assign(new Error(errorMessages[404]), {
            statusCode: errorCodes.NOT_FOUND,
          })
        }
      }
      const authors = await query

      return Object.assign(
        {
          data: {
            status: true,
            data: authors,
            totalPages: Math.ceil(totalRecords / limit),
            page,
            limit,
            totalRecords,
          },
        },
        { statusCode: errorCodes.OK }
      )
    } catch (error) {
      throw new Error('Could not retrieve books')
    }
  }

  async createBook(bookData: Book): Promise<Book> {
    try {
      const category = await CategoryModel.findById(bookData.category)
      const author = await AuthorModel.findById(bookData.author)
      console.log(category, author)
      bookData.categoryName = category.name
      bookData.authorName = author.name
      console.log(bookData)
      const book = await BookModel.create(bookData)
      return book
    } catch (error) {
      throw new Error('Could not create book')
    }
  }

  async getBookById(id: string): Promise<Book> {
    try {
      return await BookModel.findById(id)
    } catch (error) {
      throw new Error('Could not retrieve book')
    }
  }

  async updateBook(id: string, bookData: Book): Promise<Book> {
    try {
      return await BookModel.findByIdAndUpdate(id, bookData, { new: true })
    } catch (error) {
      throw new Error('Could not update book')
    }
  }

  async deleteBook(id: string): Promise<Book> {
    try {
      return await BookModel.findByIdAndDelete(id)
    } catch (error) {
      throw new Error('Could not delete book')
    }
  }

  async searchBooks(query): Promise<Book[]> {
    try {
      return await BookModel.find({
        $or: [
          { title: { $regex: query, $options: 'i' } },
          { authorName: { $regex: query, $options: 'i' } },
        ],
      })
    } catch (error) {
      throw new Error('Could not search books')
    }
  }

  async filterBooks(
    query?: string,
    minPrice?: number,
    maxPrice?: number
  ): Promise<Book[]> {
    try {
      // console.log('Query:', query);
      // console.log('minPrice', minPrice);
      // console.log('maxPrice', maxPrice);

      // Define the conditions for filtering
      const conditions: any[] = [
        {
          $or: [
            { title: query },
            { authorName: query },
            { categoryName: query },
            { ISBN: query },
          ].filter(Boolean),
        },
      ]

      // Check if publishedYear exists and add it to conditions
      if (!isNaN(Number(query))) {
        // Check if query can be converted to a number
        conditions.push({ publishedYear: Number(query) })
      }

      // Add price range condition
      conditions.push({ price: { $gte: minPrice, $lte: maxPrice } })

      // Perform the query using $and operator with conditions
      const books = await BookModel.find({ $and: conditions })

      console.log('Filtered Books:', books)
      return books
    } catch (error) {
      throw new Error('Could not filter books')
    }
  }

  async filterBooksByPrice(
    minPrice: number,
    maxPrice: number
  ): Promise<Book[]> {
    try {
      console.log('minPrice', minPrice)
      console.log('maxPrice', maxPrice)

      // Query books based on price range
      const books = await BookModel.find({
        price: { $gte: minPrice, $lte: maxPrice },
      })

      console.log('Filtered Books:', books)
      return books
    } catch (error) {
      throw new Error('Could not filter books')
    }
  }
}
