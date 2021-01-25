package cn.ctyun.oos.iam.signer;

public class ErrorMessage {
    public static final String ERROR_CODE_INCOMPLETE_BODY = "IncompleteBody";
    public static final String ERROR_MESSAGE_INCOMPLETE_BODY = "You did not provide the number of bytes specified by the Content-Length HTTP header";
    public static final String ERROR_CODE_500 = "InternalError";
    public static final String ERROR_MESSAGE_500 = "We encountered an internal error. Please try again.";
    public static final String ERROR_CODE_SLOW_DOWN = "SlowDown";
    public static final String ERROR_MESSAGE_SLOW_DOWN = "Please reduce your request rate.";
    public static final String ERROR_CODE_REQUEST_TIMEOUT = "RequestTimeout";
    public static final String ERROR_MESSAGE_REQUEST_TIMEOUT = "Your socket connection to the server was not read from or written to within the timeout period.";
    public static final String GET_OBJECT_FAILED = "GetObjectFailed";
    public static final String ERROR_CODE_INVALID_STORAGECLASS = "InvalidStorageClass";
    public static final String ERROR_MESSAGE_INVALID_STORAGECLASS = "The storage class you specified is not valid.";
    public static final String PUT_OBJECT_OVERWRITTEN = "ObjectOverWritten";
    public static final String ERROR_CODE_MALFORMEDXML = "MalformedXML";
    public static final String ERROR_MESSAGE_MALFORMEDXML = "The XML you provided was not well-formed or did not validate against our published schema";
    public static final String ERROR_CODE_INVALID_ARGUMENT = "InvalidArgument";
    public static final String ERROR_CODE_INVALID_REQUEST = "InvalidRequest";
    public static final String ERROR_CODE_INVALID_LOCATION_CONSTRAINT = "InvaildLocationConstraint";
    public static final String ERROR_MESSAGE_INVALID_LOCATION_CONSTRAINT = "The specified location constraint is not valid.";
    public static final String ERROR_CODE_CAN_NOT_MODIFY_METADATA_LOCATION = "CanNotModifyMetadataLocation";
    public static final String ERROR_MESSAGE_CAN_NOT_MODIFY_METADATA_LOCATION = "Can not modifiy bucket metadata location.";
    public static final String ERROR_CODE_405 = "MethodNotAllowed";
    public static final String ERROR_MESSAGE_405 = "The specified method is not allowed against this resource.";
    public static final String ERROR_CODE_INVALID_USER = "InvalidUser";
    public static final String ERROR_CODE_403 = "AccessDenied";
    public static final String ERROR_MESSAGE_403 = "Access Denied";
    public static final String ERROR_CODE_NO_SUCH_KEY = "NoSuchKey";
    public static final String ERROR_CODE_NO_SUCH_BUCKET = "NoSuchBucket";
    public static final String ERROR_CODE_NO_SUCH_UPLOAD = "NoSuchUpload";
    public static final String ERROR_CODE_BAD_DIGEST = "BadDigest";
    public static final String ERROR_CODE_MISSING_CONTENT_LENGTH = "MissingContentLength";
    public static final String ERROR_CODE_SIGNATURE_DOES_NOT_MATCH = "SignatureDoesNotMatch";
    public static final String ERROR_MESSAGE_404 = "The resource you requested does not exist";
    public static final String ERROR_CODE_INVALID_BUCKET_CORS_CONFIGURE = "InvaildBucketCorsConfigure";
    public static final String ERROR_MESSAGE_INVALID_BUCKET_CORS_XML_SIZE = "The maximum size of a CORS XML you provided is 64KB.";
    public static final String ERROR_CODE_NO_SUCH_BUCKET_CORS = "NoSuchCORSConfiguration";
    public static final String ERROR_MESSAGE_NO_SUCH_BUCKET_CORS = "The CORS configuration does not exist.";
    public static final String ERROR_MESSAGE_INVALID_BUCKET_CORS_XML = "The XML you provided is not valid.";
    public static final String ERROR_MESSAGE_INVALID_BUCKET_CORS_NUMBER = "The number of CORS Rules you provided cannot exceed 100.";
    public static final String ERROR_MESSAGE_BUCKET_CORS_EMPTY = "CORS Rule is empty.";
    public static final String ERROR_MESSAGE_BUCKET_CORS_ID_UNIQUE = "CORS Rule ID is not unique.";
    public static final String ERROR_MESSAGE_BUCKET_CORS_ID_LENGTH = "The length of CORS Rule ID you provided cannot exceed 255 characters.";
    public static final String ERROR_MESSAGE_INVALID_BUCKET_CORS_ALLOWEDORIGIN = "AllowedOrigin does not exist.";
    public static final String ERROR_MESSAGE_INVALID_BUCKET_CORS_ALLOWEDMETHOD = "AllowedMethod does not exist.";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_LIMITRATE = "x-amz-limitrate invalid.The input should be positive integer.";
    public static final String ERROR_MESSAGE_AUTHORITY_NOT_MATCH = "AuthorityNotMatch";
    public static final String ERROR_CODE_BUCKET_ALREADY_EXIST = "BucketAlreadyExist";
    public static final String ERROR_MESSAGE_BUCKET_ALREADY_EXIST = "Bucket already exist.";
    // V4
    public static final String ERROR_CODE_AUTH_HEADER_MALFORMED = "AuthorizationHeaderMalformed";
    public static final String ERROR_MESSAGE_AUTH_HEADER_MALFORMED = "The authorization header is malformed.";
    public static final String ERROR_MESSAGE_UNSUPPORTED_AUTH_TYPE = "Unsupported Authorization Type";
    public static final String ERROR_MESSAGE_CREDENTIAL_MALFORMED = "The authorization header is malformed; the Credential is mal-formed; expecting 'YOUR-AKID/YYYYMMDD/REGION/SERVICE/aws4_request'";
    public static final String ERROR_MESSAGE_INVALID_HOST = "OOS authentication requires a valid host header";
    public static final String ERROR_MESSAGE_MISSING_X_AMZ_CONTENT_SHA256 = "Missing required header for this request: x-amz-content-sha256";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_CONTENT_SHA256 = "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, STREAMING-AWS4-HMAC-SHA256-PAYLOAD, or a valid sha256 value.";
    public static final String ERROR_MESSAGE_INVALID_DATE_HEADER = "OOS authentication requires a valid Date or x-amz-date header.";
    public static final String ERROR_MESSAGE_INVALID_DATE_HEADER_WITH_EXPECTING = "OOS authentication requires a valid Date or x-amz-date header. expecting \" YYYYMMDD'T'HHMMSS'Z'\"";
    public static final String ERROR_MESSAGE_SIGNATURE_DOES_NOT_MATCH = "The request signature we calculated does not match the signature you provided. Check your key and signing method.";
    public static final String ERROR_MESSAGE_INVALID_SIGNED_HEADERS = "Invalid order of SignedHeaders.";
    
    public static final String ERROR_CODE_AUTH_QUERY_ERROR = "AuthorizationQueryParametersError";
    public static final String ERROR_MESSAGE_MISSING_AUTH_QUERY = "Query-string authentication version 4 requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and X-Amz-Expires parameters.";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_ALGORITHM = "X-Amz-Algorithm only supports 'AWS4-HMAC-SHA256'";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_DATE = "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_EXPIRES_TOO_LARGE = "X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires must be less than 604800 seconds";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_EXPIRES = "X-Amz-Expires must be non-negative";
    public static final String ERROR_MESSAGE_REQUEST_HAS_EXPIRED = "Request has expired";
    
    public static final String ERROR_CODE_AUTH_POST_ERROR = "AuthorizationPostFormFieldsError";
    public static final String ERROR_MESSAGE_MISSING_AUTH_POST_FORM = "Form Post authentication version 4 requires the policy, x-amz-algorithm, x-amz-credential, x-amz-signature, x-amz-date form fields.";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_ALGORITHM_FORM = "x-amz-algorithm only supports 'AWS4-HMAC-SHA256'";
    public static final String ERROR_MESSAGE_INVALID_X_AMZ_DATE_POST_FORM = "x-amz-date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"";
    public static final String ERROR_MESSAGE_INVALID_POLICY = "Invalid according to Policy: Policy expired.";

    // 多版本异常
    public static final String ERROR_CODE_ILLEGAL_VERSIONING_CONFIGURATION = "IllegalVersioningConfigurationException.";
    public static final String ERROR_MESSAGE_ILLEGAL_VERSIONING_CONFIGURATION = "The Versioning element must be specified.";
    
    public static final String ERROR_GET_POLICY ="get user policy failed";
}
