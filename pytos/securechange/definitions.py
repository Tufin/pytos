
import enum
import re


@enum.unique
class Time_Units(enum.Enum):
    Seconds = 1  # 1
    Minutes = 60 * Seconds  # 60
    Hours = 60 * Minutes  # 3600
    Days = 24 * Hours  # 86400


class Ticket_Activity(enum.Enum):
    ACCEPT = r"Accept request"
    ASK_MORE_INFO = r"Sent request for more information"
    ASSIGN = r"Assign request"
    ASSIGNER = r"Assign request to assigner"
    AUTOMATED = r"Automation executed successfully"
    AUTO_ASSIGN = r"Assign request automatically"
    CANCEL = r"Cancel request"
    CANCEL_BY_ADMIN = r"Cancel request"
    CLOSE = r"Close request"
    CONTINUE_AFTER_ASK_MORE_INFO = r"Continue working with request after more info"
    CREATE = r"Create request"
    DONE = r"Complete request's task"
    EXPIRATION_ACKNOWLEDGED = r"Acknowledge expired ticket"
    EXPIRATION_CHANGED = r"Update expiration date"
    EXPIRATION_EXPIRED = r"Mark ticket as expired"
    EXTERNAL_APPROVAL_APPROVED = r"Approved in external system"
    EXTERNAL_APPROVAL_REJECTED = r"Rejected in external system"
    INITIAL_CHECK_RAN_FOR_AUTO_CLOSE = r"Initial check ran for Auto-close."
    INVALID_HANDLER_DELETED = r"Mark request as invalid handler was deleted"
    INVALID_HANDLER_DIFFERENT_DOMAIN = r"Mark request as invalid,? handler does not have access to the ticket domain"
    INVALID_HANDLER_ON_VACATION = r"Mark request as invalid handler is on vacation"
    INVALID_PARTICIPANT_DELETED = r"Mark request as invalid no participant left"
    MOVE_STAGE = r"Move to the next step"
    PENDING_AUTOMATION = r"Move task to the pending status \(Executing automatic tasks\)"
    PENDING_AUTO_CLOSE = r"Move task to the pending status \(Initial check\)"
    PENDING_AUTO_VERIFICATION = r"Move task to the pending status \(Auto verification\)"
    PENDING_PARALLEL_CALCULATION = r"Move task to the pending status \(Dynamic assignment\)"
    PENDING_PROVISIONING = r"Move task to the pending status \(Apply Changes\)"
    PENDING_REDO = r"Move task to the pending status \(Reverting request\)"
    PENDING_SKIP_CALCULATION = r"Move task to the pending status \(Evaluate skip conditions\)"
    PENDING_USER_VERIFY_FAIL = r"Move task to the pending status \(Resubmitting request\)"
    PRIORITY_CHANGED = r"Change request priority"
    PROVISIONING_DONE = r"Apply Changes executed"
    REASSIGN = r"Reassign request"
    REDO = r"Reverted request to a previous task"
    REDO_REQUESTOR = r"Reverted request to the requester"
    REJECT = r"Reject request"
    REOPEN = r"Reopened request to a previous task"
    REPLY_RECEIVED_NOTIFICATION = r"Received reply to request for more information"
    REQUEST_EXTERNAL_APPROVAL = r"Approval requested from external system"
    RESOLVE = r"Resolve request and send to requester for confirmation"
    RESUBMIT = r"Resubmit request"
    SELFASSIGN = r"Assign request to same user"
    SELF_ASSIGN_FROM_GROUP_MEMBER = r"Self assigned from group member"
    STEP_SKIPPED = r"Step was skipped"
    SUGGEST_TARGET_FOR_AUTO_CLOSE = r"Targets automatically suggested during initial check for Auto-close."
    UPDATE_DEVICE = r"Update device"
    UPDATE_DEVICE_FAILED = r"Update device failed"
    UPDATE_DEVICE_SUCCEEDED = r"Update device succeeded"
    VERIFY = r"Verify request"

    # States with regular expressions, placed after non-regex states for correct matching.
    SUGGEST_TARGET_CANNOT_RUN_BECAUSE_ANY_OR_CLASS_A = r"Target suggestion and initial check did not run because the source or destination of AR(.+) is either ANY or a class A subnet."
    SUGGEST_TARGET_CANNOT_RUN_BECAUSE_IPV6 = r"Target suggestion and initial check did not run because the source or destination of AR(.+) is IPv6."
    SUGGEST_TARGET_CANNOT_RUN_BECAUSE_MISSING_VALUES = r"Target suggestion and initial check did not run because AR(.+) is missing a source destination or service/application identity."
    SELFASSIGN_WITH_ASSIGNEE = r"(.+) assigned ticket to self"
    STEP_AUTOMATED = r"Automatic step: (.+) completed"
    STEP_AUTOMATION_FAILED_WITH_REASON = r"Automatic step: (.+) failed due to: (.+)"
    STEP_AUTOMATION_FAILED_WITH_NO_REASON = r"Automatic step: (.+) (.+)"
    SELF_ASSIGN_FROM_GROUP_MEMBER_WITH_ASSIGNEE = r"(.+) self-assigned the task from another group member"
    REASSIGN_WITH_ASSIGNEE = r"Ticket reassigned to (.+)"
    REDO_REQUESTOR_WITH_ASSIGNEE = r"Ticket sent to (.+) to be resubmitted"
    ASSIGN_WITH_ASSIGNEE = r"Ticket assigned to (.+)"
    ASSIGNER_WITH_ASSIGNEE = r"Ticket assigned to an assigner (.+)"
    AUTO_ASSIGN_WITH_ASSIGNEE = r"Ticket automatically assigned to (.+)"
    INITIAL_CHECK_CANNOT_RUN_BECAUSE_IPV6 = r"Initial check did not run because the source or destination of AR(.+) is IPv6."
    INITIAL_CHECK_CANNOT_RUN_BECAUSE_MISSING_VALUES = r"Initial check did not run because AR(.+) is missing a source destination or service/application identity."
    INITIAL_CHECK_DID_NOT_RUN_BECAUSE_MORE_THAN_TARGETS_WERE_FOUND_FOR_AR = r"Initial check did not run because more than (.+) targets were found for AR(.+)."
    INITIAL_CHECK_DID_NOT_RUN_BECAUSE_NO_RELEVANT_TARGETS_WERE_FOUND_FOR_AR = r"Initial check did not run because no relevant targets were found for AR(.+)."
    ACCEPT_WITH_ASSIGNEE = r"Ticket accepted by (.+)"
    UPDATE_DEVICE_CP = r"update (.+) failed due to: (.+)"
    UPDATE_DEVICE_CP_SUCCEEDED = r"Update (.+) succeeded"
    UPDATE_DEVICE_DID_NOT_RUN = r"Update (.+) did not run"

    @staticmethod
    def find_matching_state(input_string):
        for item in list(Ticket_Activity):
            match = re.match(item.value, input_string)
            if match:
                return item.name, item.value, match.groups()
        raise ValueError("No matching state found for string '%s'.", input_string)

    @staticmethod
    def does_input_string_match_states(input_string, states):
        state_names = [state.name for state in states]
        try:
            state_match = Ticket_Activity.find_matching_state(input_string)
            if state_match[0] in state_names:
                return True
            else:
                return False
        except ValueError:
            return False


@enum.unique
class Email_Templates(enum.Enum):
    ACTIVITY_TICKET_ASSIGN = "Task assigned to you (manual)"
    ACTIVITY_TICKET_ASSIGNER = "Task needs to be assigned (to assigner)"
    ACTIVITY_TICKET_AUTO_ASSIGN = "Task assigned to you (auto)"
    ACTIVITY_TICKET_CANCEL = "Requester canceled request"
    ACTIVITY_TICKET_CLOSED = "Handling completed"
    ACTIVITY_TICKET_REASSIGN = "Task re-assigned to you"
    ACTIVITY_TICKET_REDO = "Redo task"
    ACTIVITY_TICKET_REDO_REQUESTOR = "Resubmit request"
    APPLICATION_ACCESS_CONFIRMED = "Request to access application completed"
    APPLICATION_ACCESS_REJECTED = "Request to access application rejected"
    APPLICATION_ACCESS_REQUESTED = "Requested access to application (to owner)"
    APPLICATION_ACCESS_REQUESTED_REQUESTER = "Request to access application submitted (to requester)"
    CONNECTION_DISCONNECTED = "Blocked connection notification"
    EXPIRED_FUTURE_NOTIFICATION = "Request expiring"
    EXPIRED_NOTIFICATION = "Request expired"
    EXTERNAL_APPROVER_NOTIFICATION = "External approver notification"
    MANUAL_RISK_NOTIFICATION = "Risks were manually disregarded"
    PARTICIPANTS_NOTIFICATION = "Task available"
    REJECT_MAIL = "Your request rejected"
    REJECT_MAIL_TO_HANDLER = "Request rejected (to task handler)"
    REPLY_RECEIVED_NOTIFICATION = "Reply received"
    REQUEST_MORE_INFO = "Provide info"
    REQUEST_OPENED = "Request opened"
    SLA_TICKET_HANDLER = "SLA status raised (handlers)"
    SLA_TICKET_SUPERVISOR = "SLA status raised (additional recipients)"
    VERIFICATION_FAILED = "Access Request verification failed"
    VERIFY_NOTIFICATION = "Confirm resolved request"
    VIRTUAL_SERVER_UPDATED = "Update Virtual server"
