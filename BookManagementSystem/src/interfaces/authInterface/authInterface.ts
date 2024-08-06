import { Request } from 'express'

export interface AuthenticatedRequest extends Request {
  user?: any
  profile?: any // Define the user property on the Request object
}
