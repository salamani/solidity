#include <test/tools/ossfuzz/protoToAbiV2.h>
#include <boost/range/algorithm_ext/erase.hpp>
#include <libsolidity/codegen/YulUtilFunctions.h>
#include <libdevcore/Whiskers.h>
#include <regex>

using namespace dev::test::abiv2fuzzer;
using namespace std;
using namespace dev::solidity;

string ProtoConverter::createAlphaNum(string const& _strBytes) const
{
	string tmp{_strBytes};
	if (!tmp.empty())
	{
		boost::range::remove_erase_if(tmp, [=](char c) -> bool {
			return !(std::isalpha(c) || std::isdigit(c));
		});
		tmp = tmp.substr(0, 32);
	}
	return tmp;
}

void ProtoConverter::visit(SignedIntegerType const& _x)
{
	unsigned width = 8 * ((_x.width() % 32) + 1);
	std::string type = "int" + std::to_string(width);
	m_output << Whiskers(R"(
	<type> x_<index> = )")
	("type", type)
	("index", std::to_string(m_varIndex))
	.render();
	visit(_x.value(), width);
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
	m_output << ";\n";
}

void ProtoConverter::visit(UnsignedIntegerType const& _x)
{
	unsigned width = 8 * ((_x.width() % 32) + 1);
	std::string type = "uint" + std::to_string(width);
	m_output << Whiskers(R"(
	<type> x_<index> = )")
	("type", type)
	("index", std::to_string(m_varIndex))
	.render();
	visit(_x.value(), width);
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
	m_output << ";\n";
}

void ProtoConverter::visit(SignedIntegerValue const& _x, unsigned _width)
{
	s256 value = generateSigned(_x.value64(), _x.value128(), _x.value192(), _x.value256());
	switch (_width)
	{
	case 8:
		m_currentValue = s8(value).str();
		break;
	case 16:
		m_currentValue = s16(value).str();
		break;
	case 24:
		m_currentValue = s24(value).str();
		break;
	case 32:
		m_currentValue = s32(value).str();
		break;
	case 40:
		m_currentValue = s40(value).str();
		break;
	case 48:
		m_currentValue = s48(value).str();
		break;
	case 56:
		m_currentValue = s56(value).str();
		break;
	case 64:
		m_currentValue = s64(value).str();
		break;
	case 72:
		m_currentValue = s72(value).str();
		break;
	case 80:
		m_currentValue = s80(value).str();
		break;
	case 88:
		m_currentValue = s88(value).str();
		break;
	case 96:
		m_currentValue = s96(value).str();
		break;
	case 104:
		m_currentValue = s104(value).str();
		break;
	case 112:
		m_currentValue = s112(value).str();
		break;
	case 120:
		m_currentValue = s120(value).str();
		break;
	case 128:
		m_currentValue = s128(value).str();
		break;
	case 136:
		m_currentValue = s136(value).str();
		break;
	case 144:
		m_currentValue = s144(value).str();
		break;
	case 152:
		m_currentValue = s152(value).str();
		break;
	case 160:
		m_currentValue = s160(value).str();
		break;
	case 168:
		m_currentValue = s168(value).str();
		break;
	case 176:
		m_currentValue = s176(value).str();
		break;
	case 184:
		m_currentValue = s184(value).str();
		break;
	case 192:
		m_currentValue = s192(value).str();
		break;
	case 200:
		m_currentValue = s200(value).str();
		break;
	case 208:
		m_currentValue = s208(value).str();
		break;
	case 216:
		m_currentValue = s216(value).str();
		break;
	case 224:
		m_currentValue = s224(value).str();
		break;
	case 232:
		m_currentValue = s232(value).str();
		break;
	case 240:
		m_currentValue = s240(value).str();
		break;
	case 248:
		m_currentValue = s248(value).str();
		break;
	case 256:
		m_currentValue = s256(value).str();
		break;
	}
	m_output << m_currentValue;
}

void ProtoConverter::visit(UnsignedIntegerValue const& _x, unsigned _width)
{
	u256 value = generateUnsigned(_x.value64(), _x.value128(), _x.value192(), _x.value256());
	switch (_width)
	{
	case 8:
		m_currentValue = u8(value).str();
		break;
	case 16:
		m_currentValue = u16(value).str();
		break;
	case 24:
		m_currentValue = u24(value).str();
		break;
	case 32:
		m_currentValue = u32(value).str();
		break;
	case 40:
		m_currentValue = u40(value).str();
		break;
	case 48:
		m_currentValue = u48(value).str();
		break;
	case 56:
		m_currentValue = u56(value).str();
		break;
	case 64:
		m_currentValue = u64(value).str();
		break;
	case 72:
		m_currentValue = u72(value).str();
		break;
	case 80:
		m_currentValue = u80(value).str();
		break;
	case 88:
		m_currentValue = u88(value).str();
		break;
	case 96:
		m_currentValue = u96(value).str();
		break;
	case 104:
		m_currentValue = u104(value).str();
		break;
	case 112:
		m_currentValue = u112(value).str();
		break;
	case 120:
		m_currentValue = u120(value).str();
		break;
	case 128:
		m_currentValue = u128(value).str();
		break;
	case 136:
		m_currentValue = u136(value).str();
		break;
	case 144:
		m_currentValue = u144(value).str();
		break;
	case 152:
		m_currentValue = u152(value).str();
		break;
	case 160:
		m_currentValue = u160(value).str();
		break;
	case 168:
		m_currentValue = u168(value).str();
		break;
	case 176:
		m_currentValue = u176(value).str();
		break;
	case 184:
		m_currentValue = u184(value).str();
		break;
	case 192:
		m_currentValue = u192(value).str();
		break;
	case 200:
		m_currentValue = u200(value).str();
		break;
	case 208:
		m_currentValue = u208(value).str();
		break;
	case 216:
		m_currentValue = u216(value).str();
		break;
	case 224:
		m_currentValue = u224(value).str();
		break;
	case 232:
		m_currentValue = u232(value).str();
		break;
	case 240:
		m_currentValue = u240(value).str();
		break;
	case 248:
		m_currentValue = u248(value).str();
		break;
	case 256:
		m_currentValue = u256(value).str();
		break;
	}
	m_output << m_currentValue;
}

// Value is enclosed within double quote e.g., "hello"
void ProtoConverter::visit(FixedByteArrayValue const& _x, unsigned _width)
{
	auto numAvailableBytes = static_cast<unsigned>(_x.value().size());
	auto usedBytes = min(_width, numAvailableBytes);
	// Length of string has to be at most usedBytes
	m_currentValue = "\"" + createAlphaNum(_x.value()).substr(0, usedBytes) + "\"";
	m_output << m_currentValue;
}

void ProtoConverter::visit(DynamicByteType const& _x)
{
	std::string type = (m_isStateVar ? "bytes": "bytes memory");
	m_output << Whiskers(R"(
	<type> x_<i> = )")
	("type", type)
	("i", std::to_string(m_varIndex))
	.render();
	visit(_x.value());
	m_output << ";\n";
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
}

void ProtoConverter::visit(DynamicStringType const& _x)
{
	std::string type = (m_isStateVar ? "string": "string memory");
	m_output << Whiskers(R"(
	<type> x_<i> = )")
	("type", type)
	("i", std::to_string(m_varIndex))
	.render();
	visit(_x.value());
	m_output << ";\n";
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
}

void ProtoConverter::visit(DynamicByteValue const& _x)
{
	// TODO: A bytes stream can be longer than 32 bytes
	// FIXME: This creates a value whose size is at most 32 bytes.
	m_currentValue = "\"" + createAlphaNum(_x.value()) + "\"";
	m_output << m_currentValue;
}

void ProtoConverter::visit(DynamicStringValue const& _x)
{
	m_currentValue = "\"" + createAlphaNum(_x.value()) + "\"";
	m_output << m_currentValue;
}

void ProtoConverter::visit(AddressValue const& _x)
{
	m_currentValue = Whiskers(R"(address(<value>))")
	("value", u160(generateUnsigned(_x.value64(), _x.value128(), _x.value160(), 0)).str())
	.render();
	m_output << m_currentValue;
}

void ProtoConverter::visit(Type const& _x)
{
	switch (_x.type_oneof_case())
	{
	case Type::kStype:
		visit(_x.stype());
		break;
	case Type::kDtype:
		visit(_x.dtype());
		break;
	case Type::TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(VarDecl const& _x)
{
	visit(_x.type());
}

void ProtoConverter::visit(Statement const& _x)
{
	switch (_x.statement_oneof_case())
	{
	case Statement::kDecl:
		visit(_x.decl());
		break;
	case Statement::kStructdef:
		visit(_x.structdef());
		break;
	case Statement::STATEMENT_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(StaticType const& _x)
{
	switch (_x.static_type_oneof_case())
	{
	case StaticType::kInteger:
		visit(_x.integer());
		break;
	case StaticType::kFbarray:
		visit(_x.fbarray());
		break;
	case StaticType::kAddress:
		visit(_x.address());
		break;
	case StaticType::kFsarray:
		visit(_x.fsarray());
		break;
	case StaticType::STATIC_TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(StructType const&)
{
}

void ProtoConverter::visit(AddressType const& _x)
{
	string type;
	switch (_x.atype())
	{
	case AddressType::ADDRESS:
		type = "address";
		m_output << Whiskers(R"(
	<type> x_<i> = )"
		)
		("type", type)
		("i", std::to_string(m_varIndex))
		.render();
		break;
	case AddressType::PAYABLE:
		type = "address payable";
		m_output << Whiskers(R"(
	<type> x_<i> = )"
		)
		("type", type)
		("i", std::to_string(m_varIndex))
		.render();
		break;
	}
	visit(_x.value());
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
	m_output << ";\n";
}

void ProtoConverter::visit(DynamicType const& _x)
{
	switch (_x.dynamic_type_oneof_case())
	{
	case DynamicType::kStructtype:
		visit(_x.structtype());
		break;
	case DynamicType::kDynbytearray:
		visit(_x.dynbytearray());
		break;
	case DynamicType::DYNAMIC_TYPE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(IntegerType const& _x)
{
	switch (_x.integer_type_case())
	{
	case IntegerType::kSint:
		visit(_x.sint());
		break;
	case IntegerType::kUint:
		visit(_x.uint());
		break;
	case IntegerType::INTEGER_TYPE_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(StructTypeDefinition const&)
{
}

void ProtoConverter::visit(FixedByteArrayType const& _x)
{
	unsigned numBytes = (_x.width() % 32) + 1;
	std::string type = "bytes" + std::to_string(numBytes);
	m_output << Whiskers(R"(
	<type> x_<i> = )"
	)
	("type", type)
	("i", std::to_string(m_varIndex))
	.render();
	visit(_x.value(), numBytes);
	m_typeLocValueMap.insert(make_pair(m_varIndex++, make_tuple(type, m_isStateVar, m_currentValue)));
	m_output << ";\n";
}

void ProtoConverter::visit(DynamicByteArrayType const& _x)
{
	switch (_x.dynamic_byte_oneof_case())
	{
	case DynamicByteArrayType::kByte:
		visit(_x.byte());
		break;
	case DynamicByteArrayType::kString:
		visit(_x.string());
		break;
	case DynamicByteArrayType::DYNAMIC_BYTE_ONEOF_NOT_SET:
		break;
	}
}

void ProtoConverter::visit(FixedSizeArrayType const&)
{
}

// Called by g()
std::string ProtoConverter::equalityChecksAsString()
{
	ostringstream out;

	for (auto const& kv: m_typeLocValueMap)
	{
		if (get<0>(kv.second) == "string" || get<0>(kv.second) == "string memory")
				out << Whiskers(R"(
		if (!stringCompare(g_<i>, x_<i>)) return false;
				)")("i", std::to_string(kv.first)).render();
		else if (get<0>(kv.second) == "bytes" || get<0>(kv.second) == "bytes memory")
				out << Whiskers(R"(
		if (!bytesCompare(g_<i>, x_<i>)) return false;
				)")("i", std::to_string(kv.first)).render();
		else
				out << Whiskers(R"(
		if (g_<i> != x_<i>) return false;
				)")("i", std::to_string(kv.first)).render();
	}
	return out.str();
}

std::string ProtoConverter::dataLocationToStr(dataLocation _loc)
{
	switch (_loc)
	{
	case dataLocation::STORAGE:
		return "storage";
	case dataLocation::MEMORY:
		return "memory";
	case dataLocation::CALLDATA:
		return "calldata";
	}
}

std::string ProtoConverter::typedParametersAsString(dataLocation _loc)
{
	ostringstream out;
	// FIXME: Don't depend on size of m_typeLocValueMap == m_varIndex
	assert(m_typeLocValueMap.size() == m_varIndex);
	for (auto const& kv : m_typeLocValueMap)
	{
		if (get<0>(kv.second) == "bytes" || get<0>(kv.second) == "string")
			out << Whiskers(R"(<type> <location> g_<i><delimiter>)")
			("type", get<0>(kv.second))
			("location", dataLocationToStr(_loc))
			("i", std::to_string(kv.first))
			("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
			.render();
		else if (get<0>(kv.second) == "bytes memory" || get<0>(kv.second) == "string memory")
			out << Whiskers(R"(<?calldata><calldata_type><!calldata><memory_type></calldata> g_<i><delimiter>)")
					("calldata", (_loc == dataLocation::CALLDATA))
					("calldata_type", std::regex_replace(get<0>(kv.second), std::regex("memory"), std::string("calldata")))
					("memory_type", get<0>(kv.second))
					("i", std::to_string(kv.first))
					("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
					.render();
		else
			out << Whiskers(R"(<type> g_<i><delimiter>)")
			("type", get<0>(kv.second))
			("i", std::to_string(kv.first))
			("delimiter", (kv.first == (m_varIndex - 1) ? "" : ", "))
			.render();
	}
	return out.str();
}

std::string ProtoConverter::copyLocalVarsAsString()
{
	ostringstream out;
	for (auto const& kv : m_typeLocValueMap)
	{
		if (!get<1>(kv.second))
			out << Whiskers(R"(
        <type> x_<i> = <value>;)")
			("type", get<0>(kv.second))
			("i", std::to_string(kv.first))
			("value", get<2>(kv.second))
			.render();
	}
	return out.str();
}

// Caller function
void ProtoConverter::visit(TestFunction const& _x)
{
	m_output << Whiskers(R"(
	function f() public returns (bool) {
	)")
	.render();

	for (auto const& s: _x.statements())
		visit(s);

	m_output << Whiskers(R"(
		return (this.g_public(<parameter_names>) && this.g_external(<parameter_names>));
	}
	)")
	("parameter_names", YulUtilFunctions::suffixedVariableNameList("x_", 0, m_varIndex))
	.render();
}

void ProtoConverter::writeHelperFunctions()
{
	m_output << Whiskers(R"(
	function stringCompare(string memory a, string memory b) internal pure returns (bool) {
		if(bytes(a).length != bytes(b).length) {
			return false;
		} else {
			return keccak256(bytes(a)) == keccak256(bytes(b));
		}
	}
	)").render();

	m_output << Whiskers(R"(
	function bytesCompare(bytes memory a, bytes memory b) internal pure returns (bool) {
		if(a.length != b.length)
			return false;
		for (uint i = 0; i < a.length; i++)
			if (a[i] != b[i])
				return false;
		return true;
	}
	)").render();

	// These are callee functions that encode from storage, decode to
	// memory/calldata and check if decoded value matches storage value
	// return true on successful match, false otherwise
	m_output << Whiskers(R"(
	function g_public(<parameters_memory>) public view returns (bool) {
		<localVar_copies>
		<equality_checks>
		return true;
	}

	function g_external(<parameters_calldata>) external view returns (bool) {
		<localVar_copies>
		<equality_checks>
		return true;
	}
	)"
	)
	("parameters_memory", typedParametersAsString(dataLocation::MEMORY))
	("localVar_copies", copyLocalVarsAsString())
	("equality_checks", equalityChecksAsString())
	("parameters_calldata", typedParametersAsString(dataLocation::CALLDATA))
	.render();
}

void ProtoConverter::visit(Contract const& _x)
{
	m_output << Whiskers(R"(pragma solidity >=0.0;
pragma experimental ABIEncoderV2;

contract C {
)").render();
	// Storage vars
	// Dynamic types
	//  struct S { uint16 u; int8 v; }
	// Var decls (mix of static and dynamic types)
	//  bool[] x;
	//  uint16 y;
	//  S s;
	for (auto const& cs: _x.cstatements())
		visit(cs);
	m_isStateVar = false;
	// Test function
	visit(_x.testfunction());
	writeHelperFunctions();
	m_output << "\n}";
}

string ProtoConverter::contractToString(Contract const& _input)
{
	visit(_input);
	return m_output.str();
}