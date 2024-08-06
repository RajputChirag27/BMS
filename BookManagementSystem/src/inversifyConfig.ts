import { Container } from 'inversify'
import * as controller from './controllers'
import * as repository from './repositories'
import * as service from './services/index'
import * as middleware from './middlewares'
import * as validator from './validations'
import { TYPES } from './types/types'
import CustomError from './helpers/customError'
const container = new Container()

//  controllers
for (const controllerName in controller) {
  const Controller = controller[controllerName]
  container.bind<typeof Controller>(Controller).to(Controller)
}
// container.bind<controller.AuthorController>(controller.AuthorController).toSelf();

//  services
for (const serviceName in service) {
  const Service = service[serviceName]
  container.bind<typeof Service>(Service).to(Service)
}

// middlewares
for (const middlewareName in middleware) {
  const Middleware = middleware[middlewareName]
  container.bind<typeof Middleware>(Middleware).to(Middleware)
}

// container.bind<middleware.ValidatorMiddleWare>(middleware.ValidatorMiddleWare).toSelf();

// repositories
for (const repositoryName in repository) {
  const Repository = repository[repositoryName]
  container.bind<typeof Repository>(Repository).to(Repository)
}

for (const validatorName in validator) {
  const Validator = validator[validatorName]
  container.bind<typeof Validator>(Validator).to(Validator)
}

container.bind<CustomError>(CustomError).to(CustomError)

export default container
