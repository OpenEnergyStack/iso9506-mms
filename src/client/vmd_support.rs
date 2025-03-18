//! Client interface for VMD Support Protocol [ISO 9506-2:2003 Section 10]

use std::time::Duration;

use super::Client;
use crate::{error::Error, messages::iso_9506_mms_1::*};

const PAGINATED_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

impl Client {
    /// Status [ISO 9506-2:2003 Section 10.3]
    pub async fn status(&self, extended_derivation: bool) -> Result<Status, Error> {
        let req = ConfirmedServiceRequest::status(StatusRequest(extended_derivation));

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::status(resp) => Ok(resp.0),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// GetNameList [ISO 9506-2:2003 Section 10.5]
    pub async fn get_name_list(
        &self,
        object_class: ObjectClass,
        object_scope: GetNameListRequestObjectScope,
    ) -> Result<Vec<Identifier>, Error> {
        // Apply timeout across all paginated requests to safeguard against
        // a server malfunction that results in infinite requests.
        tokio::time::timeout(PAGINATED_REQUEST_TIMEOUT, async {
            let mut more = true;
            let mut list = Vec::new();

            while more {
                let req = ConfirmedServiceRequest::getNameList(GetNameListRequest {
                    object_class: object_class.clone(),
                    object_scope: object_scope.clone(),
                    continue_after: list.last().cloned(),
                });

                let resp = self.request(req, None).await?;

                match resp {
                    ConfirmedServiceResponse::getNameList(mut resp) => {
                        list.append(&mut resp.list_of_identifier);
                        more = resp.more_follows;
                    }
                    _ => return Err(Error::BadResponse("mismatched service response".into())),
                }
            }

            Ok(list)
        })
        .await?
    }

    /// Identify [ISO 9506-2:2003 Section 10.6]
    pub async fn identify(&self) -> Result<IdentifyResponse, Error> {
        let req = ConfirmedServiceRequest::identify(IdentifyRequest(()));

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::identify(resp) => Ok(resp),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// Rename [ISO 9506-2:2003 Section 10.7]
    pub async fn rename(
        &self,
        object_class: ObjectClass,
        current_name: ObjectName,
        new_identifier: Identifier,
    ) -> Result<(), Error> {
        let req = ConfirmedServiceRequest::rename(RenameRequest {
            object_class,
            current_name,
            new_identifier,
        });

        let resp = self.request(req, None).await?;

        match resp {
            ConfirmedServiceResponse::rename(_) => Ok(()),
            _ => Err(Error::BadResponse("mismatched service response".into())),
        }
    }

    /// GetCapabilityList [ISO 9506-2:2003 Section 10.8]
    pub async fn get_capability_list(&self) -> Result<Vec<MMSString>, Error> {
        // Apply timeout across all paginated requests to safeguard against
        // a server malfunction that results in infinite requests.
        tokio::time::timeout(PAGINATED_REQUEST_TIMEOUT, async {
            let mut more = true;
            let mut list = Vec::new();

            while more {
                let req = ConfirmedServiceRequest::getCapabilityList(GetCapabilityListRequest {
                    continue_after: list.last().cloned(),
                });

                let resp = self.request(req, None).await?;

                match resp {
                    ConfirmedServiceResponse::getCapabilityList(mut resp) => {
                        list.append(&mut resp.list_of_capabilities);
                        more = resp.more_follows;
                    }
                    _ => return Err(Error::BadResponse("mismatched service response".into())),
                }
            }

            Ok(list)
        })
        .await?
    }
}
