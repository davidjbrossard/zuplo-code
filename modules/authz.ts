import { ZuploContext, ZuploRequest, HttpProblems } from "@zuplo/runtime";

type MyPolicyOptionsType = {
  myOption: any;
};
export interface AuthZResponse {
  Decision: string;
}
export interface AuthZDecision {
  //Response: [{"Decision":"NotApplicable"}]
    Response?: [AuthZResponse];
}
export default async function (
  request: ZuploRequest,
  context: ZuploContext,
  options: MyPolicyOptionsType,
  policyName: string
) {
  // your policy code goes here, and can use the options to perform any
  // configuration
  // See the docs: https://www.zuplo.com/docs/policies/custom-code-inbound
  /*if (request.user.sub!="example"){
    return HttpProblems.forbidden(request,context);
  }*/
  const subject = '"AccessSubject": {"Attribute": [{"AttributeId":"axiomatics.demo.user.userId","Value":"Dan"},{"AttributeId": "user.employeeId","Value": "'+request.user.sub+'"}]}';
  const action = '"Action":{"Attribute":[{"AttributeId":"axiomatics.demo.action.actionId","Value":"'+request.method.toUpperCase()+'"}]}';
  const resource = '"Resource":{"Attribute":[{"AttributeId":"axiomatics.demo.api.path","Value":"record"},{"AttributeId":"axiomatics.demo.record.recordId","Value":"131"}]}';
  const authzRequest = '{"Request":{'+subject+','+action+','+resource+'}}';

  context.log.debug("request"+authzRequest);
  const response = await fetch("http://ec2-3-92-139-55.compute-1.amazonaws.com:80/authorize", {
    method: 'POST',
    body: authzRequest,
    headers: {'Content-Type': 'application/json; charset=UTF-8','Authorization':'Basic YWRzLXVzZXI6ZTVPeCVZck8jQEFkdmQ3V05DIWY='} 
  });

  if (!response.ok) { 
    context.log.error(response);
    return HttpProblems.badRequest(request,context);
   } else {
    // If you care about a response:
    let authorized:boolean = false;
    if (response.body !== null) {
      const decision = await response.json();
      context.log.debug("PDP says: ", decision);
      context.log.debug(decision.keys);
      if (authorized){
        context.log.debug("about to return request");
        return request;
      } else {
        context.log.debug("about to 403");
        return HttpProblems.forbidden(request,context);
      }
    } else {
      return HttpProblems.badRequest(request,context);
    }

  }

}