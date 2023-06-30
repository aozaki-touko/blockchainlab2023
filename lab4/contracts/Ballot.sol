// 版本声明
pragma solidity >=0.4.22 <0.9.0;

contract Voting {

    // 这里使用字典来存储候选人的票数
    mapping (bytes32 => uint8) public votesReceived;

    // 定义一个固定的候选人数组
    bytes32[] public candidateList;

    // 在构造函数中初始化候选人名单
//    constructor(bytes32[] memory candidateNames) {
//        candidateList = candidateNames;
//    }

    // 对指定候选人进行投票
    function voteForCandidate(bytes32 voter,bytes32 candidate) public {
        require(validCandidate(candidate));
        require(validCandidate(voter));
        votesReceived[candidate] += 1;
    }
    function addVoter(bytes32 candidate) public {
        candidateList.push(candidate);
        votesReceived[candidate] = 0;
    }
    // 获取某一候选人的总票数
    function totalVotesFor(bytes32 candidate) view public returns (uint8) {
        require(validCandidate(candidate));
        return votesReceived[candidate];
    }
    function getCandidate(uint index) public view returns (bytes32) {
        return candidateList[index];
    }
    // 验证候选人是否在候选人名单之内
    function validCandidate(bytes32 candidate) view public returns (bool) {
        for(uint i = 0; i < candidateList.length; i++) {
            if (candidateList[i] == candidate) {
                return true;
            }
        }
        return false;
    }

    // 获取获得最多投票的候选人
    function candidateWithMostVotes() public view returns (bytes32) {
        bytes32 candidateWithMaxVotes = candidateList[0];
        uint8 maxVotes = votesReceived[candidateList[0]];
        for(uint i = 1; i < candidateList.length; i++) {
            if (votesReceived[candidateList[i]] > maxVotes) {
                candidateWithMaxVotes = candidateList[i];
                maxVotes = votesReceived[candidateList[i]];
            }
        }
        return candidateWithMaxVotes;
    }
}