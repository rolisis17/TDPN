package app

import rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"

const (
	testRewardAccruedAtUnix   int64 = 1700000000
	testRewardPayoutStartUnix int64 = 1699833600
	testRewardPayoutEndUnix   int64 = 1700438400
)

func withTestRewardPayout(record rewardstypes.RewardAccrual) rewardstypes.RewardAccrual {
	if record.AccruedAtUnix == 0 {
		record.AccruedAtUnix = testRewardAccruedAtUnix
	}
	if record.PayoutStartUnix == 0 {
		record.PayoutStartUnix = testRewardPayoutStartUnix
	}
	if record.PayoutEndUnix == 0 {
		record.PayoutEndUnix = testRewardPayoutEndUnix
	}
	return record
}
