from fastmcp import FastMCP

mcp = FastMCP("D3FEND Test Server")

@mcp.tool()
def test_connection() -> str:
    """Test if MCP server is working"""
    return "D3FEND server connected successfully!"

if __name__ == "__main__":
    mcp.run()
