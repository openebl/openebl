package util

import (
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/model/trade_document/bill_of_lading/dcsa_v2"
)

func Ptr[V string | bool | dcsa_v2.PartyFunction | model.DateTime](s V) *V {
	return &s
}
