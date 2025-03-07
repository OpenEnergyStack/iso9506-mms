//! Client interface for Variable Access Protocol [ISO 9506-2:2003 Section 14]

use super::Client;
use crate::error::Error;
use crate::messages::{iso_9506_mms_1::*, mms_object_module_1::*};

impl Client {
    /// Read [ISO 9506-2:2003 Section 14.6]
    /// Note: `specificationWithResult` field hard-coded to `false`.
    pub async fn read(&self, specification: VariableAccessSpecification) -> Result<Vec<AccessResult>, Error> {
        let req = ConfirmedServiceRequest::read(ReadRequest {
            specification_with_result: false,
            variable_access_specification: specification,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::read(resp) => Ok(resp.list_of_access_result),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// Write [ISO 9506-2:2003 Section 14.7]
    pub async fn write(
        &self,
        specification: VariableAccessSpecification,
        data: Vec<Data>,
    ) -> Result<Vec<AnonymousWriteResponse>, Error> {
        let req = ConfirmedServiceRequest::write(WriteRequest {
            variable_access_specification: specification,
            list_of_data: data,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::write(resp) => Ok(resp.0),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// GetVariableAccessAttributes [ISO 9506-2:2003 Section 14.9]
    pub async fn get_variable_access_attributes(
        &self,
        req: GetVariableAccessAttributesRequest,
    ) -> Result<GetVariableAccessAttributesResponse, Error> {
        let req = ConfirmedServiceRequest::getVariableAccessAttributes(req);

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::getVariableAccessAttributes(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DefineNamedVariable [ISO 9506-2:2003 Section 14.10]
    pub async fn define_named_variable(
        &self,
        name: ObjectName,
        address: Address,
        specification: Option<TypeSpecification>,
    ) -> Result<(), Error> {
        let req = ConfirmedServiceRequest::defineNamedVariable(DefineNamedVariableRequest {
            variable_name: name,
            address,
            type_specification: specification,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::defineNamedVariable(_) => Ok(()),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DeleteVariableAccess [ISO 9506-2:2003 Section 14.11]
    /// `scope` parameter values: specific(0), aa-specific(1), domain(2), vmd(3)
    pub async fn delete_variable_access(
        &self,
        scope: u8,
        names: Option<Vec<ObjectName>>,
        domain: Option<Identifier>,
    ) -> Result<DeleteVariableAccessResponse, Error> {
        let req = ConfirmedServiceRequest::deleteVariableAccess(DeleteVariableAccessRequest {
            scope_of_delete: scope,
            list_of_name: names,
            domain_name: domain,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::deleteVariableAccess(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DefineNamedVariableList [ISO 9506-2:2003 Section 14.12]
    pub async fn define_named_variable_list(
        &self,
        name: ObjectName,
        list: Vec<AnonymousDefineNamedVariableListRequestListOfVariable>,
    ) -> Result<(), Error> {
        let req = ConfirmedServiceRequest::defineNamedVariableList(DefineNamedVariableListRequest {
            variable_list_name: name,
            list_of_variable: DefineNamedVariableListRequestListOfVariable(list),
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::defineNamedVariableList(_) => Ok(()),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// GetNamedVariableListAttributes [ISO 9506-2:2003 Section 14.13]
    pub async fn get_named_variable_list_attributes(
        &self,
        name: ObjectName,
    ) -> Result<GetNamedVariableListAttributesResponse, Error> {
        let req = ConfirmedServiceRequest::getNamedVariableListAttributes(GetNamedVariableListAttributesRequest(name));

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::getNamedVariableListAttributes(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DeleteNamedVariableList-Request [ISO 9506-2:2003 Section 14.14]
    /// `scope` parameter values: specific(0), aa-specific(1), domain(2), vmd(3)
    pub async fn delete_named_variable_list(
        &self,
        scope: u8,
        names: Option<Vec<ObjectName>>,
        domain: Option<Identifier>,
    ) -> Result<DeleteNamedVariableListResponse, Error> {
        let req = ConfirmedServiceRequest::deleteNamedVariableList(DeleteNamedVariableListRequest {
            scope_of_delete: scope,
            list_of_variable_list_name: names,
            domain_name: domain,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::deleteNamedVariableList(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DefineNamedType [ISO 9506-2:2003 Section 14.15]
    pub async fn define_named_type(&self, name: ObjectName, specification: TypeSpecification) -> Result<(), Error> {
        let req = ConfirmedServiceRequest::defineNamedType(DefineNamedTypeRequest {
            type_name: name,
            type_specification: specification,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::defineNamedType(_) => Ok(()),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// GetNamedTypeAttributes [ISO 9506-2:2003 Section 14.16]
    pub async fn get_named_type_attributes(&self, name: ObjectName) -> Result<GetNamedTypeAttributesResponse, Error> {
        let req = ConfirmedServiceRequest::getNamedTypeAttributes(GetNamedTypeAttributesRequest(name));

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::getNamedTypeAttributes(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// DeleteNamedType [ISO 9506-2:2003 Section 14.17]
    pub async fn delete_named_type(
        &self,
        scope: u8,
        names: Option<Vec<ObjectName>>,
        domain: Option<Identifier>,
    ) -> Result<DeleteNamedTypeResponse, Error> {
        let req = ConfirmedServiceRequest::deleteNamedType(DeleteNamedTypeRequest {
            scope_of_delete: scope,
            list_of_type_name: names,
            domain_name: domain,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::deleteNamedType(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }
}
