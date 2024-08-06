import mongoose from 'mongoose'
import { config } from 'dotenv'
config()
const url = process.env.URL

export const connection = async(url) =>{
  try{
  const connection = await mongoose.connect(url);
  console.log('Connected Database Successfully :', connection);}
  catch(err){
    console.log(err);
    process.exit(1);
  }
}
