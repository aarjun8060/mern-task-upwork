 
// for create one as well as create many
export const dbServiceCreate = (model, data) => {
  console.log("model",model)
  try {
   const result = model.create(data);
   console.log("result",result)
   if(result){
    return result
   }else{
    return false;
   }
  } catch (error) {
    console.log("Error in Create function in dbservices",error.message ? error.message : error)
  }

}; 

// Update Single document that will return updated Document 
export const dbServiceUpdateOne = async (model,filter,data,options={new:true}) => {
  try {
    const result = await model.findOneAndUpdate(filter,data,options)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

// update Multiple documents and return count
export const dbServiceUpdateMany = async (model,filter,options) => {
  try {
    const result = await model.updateMany(filter,options)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

// Delete Single Document that will return updated document
export const  dbServiceDeleteOne = async (model,filter,option={new:true}) => {
  try {
    const result = await model.findOneAndDelete(filter,option)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

// Delete multiple Documents and return count
export const dbServiceDeleteMany = async(model,filter,options={new:true}) => {
  try {
    const result = await model.deleteMany(filter,options)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

// find any single document by query 
export const dbServiceFindOne = async (model,filter,options={}) => {
  try {
    const result = await model.findOne(filter,options)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

// find many documnents
export const dbServiceFindMany = async (model,filter,options={}) => {
  try {
    const result = await model.find(filter,options)
    if(result){
      return result
    }else{
      return 
    }
  } catch (error) {
    console.log("Error in DB Service FindOne",error.message ? error.message : error)
  }
}

  // count documents
  export const dbServiceCount = async (model, filter) => {
    const result = await model.countDocuments(filter);
    if(result){
      return result
    }else{
      return
    }
  };

  // find documents with pagination
  export const dbServicePaginate = async(model, filter, options) => {
    const result = await model.paginate(filter, options) 
    if(result){
      return result
    }else{
      return 
    }
  }
