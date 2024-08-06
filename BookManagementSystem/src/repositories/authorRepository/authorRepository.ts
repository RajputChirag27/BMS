import { injectable } from 'inversify'
import { Author } from '../../interfaces'
import { AuthorModel } from '../../models'
import { errorCodes } from '../../constants'
import { errorMessages } from '../../constants/message'
import CustomError from '../../helpers/customError'

@injectable()
export class AuthorRepository {
  public async getAuthors(queries) {
    try {
      let queryObject = { ...queries }

      // Basic Filtaration
      const excludeFields = [
        'page',
        'sort',
        'limit',
        'fields',
        'filter',
        'search',
      ]
      excludeFields.forEach(item => delete queryObject[item])

      // Advance Filtering

      // Search on the basis of the name of the Author

      if (queries.filter) {
        const filterFields = queries.filter
        for (const field of Object.keys(filterFields)) {
          if (filterFields[field]) {
            queryObject[field] = filterFields[field]
          }
        }
      }

      let queryString = JSON.stringify(queryObject)

      queryString = queryString.replace(
        /\b(gte|gt|lte|lt|eq)\b/g,
        match => `$${match}`
      )

      console.log(queryString)

      queryObject = JSON.parse(queryString)

      // Dynamic Searching

      if (queries.search) {
        // Convert queries.search to string if it's not already a string
        if (typeof queries.search !== 'string') {
          queries.search = queries.search.toString()
        }

        const searchRegex = new RegExp(queries.search, 'i') // Create a case-insensitive regex
        console.log('searchRegex: ' + searchRegex)

        // Check if the search query is a valid number
        const searchNumber = !isNaN(queries.search)
          ? Number(queries.search)
          : null
        console.log(searchNumber)

        const searchConditions = Object.keys(AuthorModel.schema.paths).reduce(
          (conditions, field) => {
            const fieldType = AuthorModel.schema.paths[field].instance

            if (fieldType === 'String' && searchNumber === null) {
              console.log('string')
              // Add regex condition for string fields
              conditions.push({ [field]: searchRegex })
            } else if (fieldType === 'Number' && searchNumber !== null) {
              // Add exact match condition for number fields
              console.log('number')
              conditions.push({ [field]: searchNumber })
            }
            // Optionally, handle other field types here
            return conditions
          },
          []
        )

        queryObject.$or = searchConditions
      }

      // console.log("Final: "+ queryObject)
      let query = AuthorModel.find({ ...queryObject })
      const countQuery = AuthorModel.find({ ...queryObject })

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
        numOfRecords = await AuthorModel.countDocuments({ ...queryObject })
        if (skip > numOfRecords) {
          throw new CustomError(
            errorMessages[404],
            errorCodes.NOT_FOUND,
            'NoContent'
          )
        }
      }

      // Sorting
      if (queries.sort) {
        const sortBy = (queries.sort as string).split(',').join(' ')
        query = query.sort(sortBy)
      } else {
        query = query.sort({ createdAt: -1 })
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
    } catch (err) {
      // console.log(err.stack);
      throw new CustomError(
        'This is cast Error',
        errorCodes.BAD_REQUEST,
        err.name
      )
    }
  }

  public async createAuthor(author: Author): Promise<Author> {
    if (author) {
      return await AuthorModel.create(author)
    } else {
      throw new CustomError(
        'Author is not defined',
        errorCodes.NOT_IMPLEMENTED,
        'NotDefined'
      )
    }
  }

  async updateAuthor(id: string, author: Author): Promise<Author | null> {
    try {
      const updated = await AuthorModel.findOneAndUpdate({ _id: id }, author, {
        new: true,
      }).exec()
      return updated
    } catch (err) {
      throw err
    }
  }
  async deleteAuthor(id: string) {
    try {
      const deleted = await AuthorModel.findOneAndDelete({ _id: id }).exec()
      return deleted
    } catch (err) {
      throw err
    }
  }
}
