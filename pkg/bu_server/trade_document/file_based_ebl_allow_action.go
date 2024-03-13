package trade_document

import (
	"fmt"

	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading"
)

type FileBasedEBLAction string

const (
	// FileBasedEBLActionAllow is the constant for allow action
	FILE_EBL_UPDATE_DRAFT  FileBasedEBLAction = "UPDATE_DRAFT"
	FILE_EBL_AMEND         FileBasedEBLAction = "AMEND"
	FILE_EBL_REQUEST_AMEND FileBasedEBLAction = "REQUEST_AMEND"
	FILE_EBL_PRINT         FileBasedEBLAction = "PRINT"
	FILE_EBL_TRANSFER      FileBasedEBLAction = "TRANSFER"
	FILE_EBL_RETURN        FileBasedEBLAction = "RETURN"
	FILE_EBL_SURRENDER     FileBasedEBLAction = "SURRENDER"
	FILE_EBL_ACCOMPLISH    FileBasedEBLAction = "ACCOMPLISH"
	FILE_EBL_DELETE        FileBasedEBLAction = "DELETE"
)

type _AllowActionChecker func(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error

var _allowActionChecker = map[FileBasedEBLAction]_AllowActionChecker{
	FILE_EBL_UPDATE_DRAFT:  IsFileEBLUpdatable,
	FILE_EBL_AMEND:         IsFileEBLAmendable,
	FILE_EBL_REQUEST_AMEND: IsFileEBLRequestAmendable,
	FILE_EBL_PRINT:         IsFileEBLPrintable,
	FILE_EBL_TRANSFER:      IsFileEBLTransferable,
	FILE_EBL_RETURN:        IsFileEBLReturnable,
	FILE_EBL_SURRENDER:     IsFileEBLSurrenderable,
	FILE_EBL_ACCOMPLISH:    IsFileEBLAccomplishable,
	FILE_EBL_DELETE:        IsFileEBLDeletable,
}

func GetFileBasedEBLAllowActions(bl *bill_of_lading.BillOfLadingPack, bu string) []FileBasedEBLAction {
	if bl == nil || bu == "" {
		return nil
	}

	actionList := []FileBasedEBLAction{
		FILE_EBL_UPDATE_DRAFT,
		FILE_EBL_AMEND,
		FILE_EBL_REQUEST_AMEND,
		FILE_EBL_PRINT,
		FILE_EBL_TRANSFER,
		FILE_EBL_RETURN,
		FILE_EBL_SURRENDER,
		FILE_EBL_ACCOMPLISH,
		FILE_EBL_DELETE,
	}

	var actions []FileBasedEBLAction
	for _, action := range actionList {
		if err := CheckFileBasedEBLAllowAction(action, bl, bu, false); err == nil {
			actions = append(actions, action)
		}
	}

	if len(actions) == 0 {
		return nil
	}
	return actions
}

func CheckFileBasedEBLAllowAction(action FileBasedEBLAction, bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	checker, ok := _allowActionChecker[action]
	if !ok && withDetail {
		return fmt.Errorf("%s is unknown action%w", action, model.ErrEBLActionNotAllowed)
	} else if !ok {
		return model.ErrEBLActionNotAllowed
	}

	return checker(bl, bu, withDetail)
}

func IsFileEBLUpdatable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || !*draft {
		if withDetail {
			return fmt.Errorf("not draft eB/L%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	if issuer := GetIssuer(bl); issuer == nil || *issuer != bu {
		if withDetail {
			return fmt.Errorf("not the issuer%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLAmendable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("draft eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.AmendmentRequest == nil && lastEvent.Return == nil {
		if withDetail {
			return fmt.Errorf("no previous amendment request or return%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if to != bu {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	participants := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if bu != participants.Issuer {
		if withDetail {
			return fmt.Errorf("not the issuer%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLRequestAmendable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("draft eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not amendment requestable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if bu != to {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	parties := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if bu != parties.Shipper && bu != parties.Consignee && bu != parties.ReleaseAgent {
		if withDetail {
			return fmt.Errorf("only [shipper, consignee, release_agent] can request amendment. %w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed

	}

	return nil
}

func IsFileEBLPrintable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("not printable due to the bill of lading is draft%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not printable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if bu != to {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLTransferable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("draft eB/L%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not transferable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if bu != to {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	participants := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if bu != participants.Issuer && bu != participants.Shipper {
		if withDetail {
			return fmt.Errorf("not the [issuer, shipper]. %w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if bu == participants.Issuer && lastEvent.Return == nil {
		if withDetail {
			return fmt.Errorf("not transferable for the issuer%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLReturnable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("draft eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not returnable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if to != bu {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	// Identify the role of the bu.
	participants := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if participants.Issuer == bu && lastEvent.AmendmentRequest == nil {
		if withDetail {
			return fmt.Errorf("not returnable for the issuer%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	} else if participants.ReleaseAgent == bu && lastEvent.Surrender == nil {
		if withDetail {
			return fmt.Errorf("not returnable for the release agent%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLSurrenderable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft == nil || *draft {
		if withDetail {
			return fmt.Errorf("draft eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not surrenderable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if to != bu {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	participants := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if participants.Consignee != bu {
		if withDetail {
			return fmt.Errorf("not the consignee%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLAccomplishable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	lastEvent := GetLastEvent(bl)
	if lastEvent == nil {
		if withDetail {
			return fmt.Errorf("empty eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}
	if lastEvent.Accomplish != nil || lastEvent.PrintToPaper != nil {
		if withDetail {
			return fmt.Errorf("not accomplishable due to the bill of lading is printed or accomplished%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	_, to := GetOwnerShipTransferringByEvent(lastEvent)
	if to != bu {
		if withDetail {
			return fmt.Errorf("not the owner%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	participants := GetFileBaseEBLParticipatorsFromBLPack(bl)
	if participants.ReleaseAgent != bu {
		if withDetail {
			return fmt.Errorf("not the release_agent%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}

func IsFileEBLDeletable(bl *bill_of_lading.BillOfLadingPack, bu string, withDetail bool) error {
	if draft := GetDraft(bl); draft != nil && !*draft {
		if withDetail {
			return fmt.Errorf("not draft eBL%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	if issuer := GetIssuer(bl); issuer == nil || *issuer != bu {
		if withDetail {
			return fmt.Errorf("not the issuer%w", model.ErrEBLActionNotAllowed)
		}
		return model.ErrEBLActionNotAllowed
	}

	return nil
}
