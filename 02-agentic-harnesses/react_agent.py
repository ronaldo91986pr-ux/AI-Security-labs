import re

class SimpleReActAgent:
    def __init__(self, tools, llm_client):
        self.tools = tools
        self.llm_client = llm_client
        self.history = []

    def run(self, user_prompt: str, max_steps: int = 5):
        self.history.append(f"User: {user_prompt}")
        for step in range(max_steps):
            # Build prompt with execution history
            prompt = "\n".join(self.history) + "\nThought:"
            response = self.llm_client(prompt)
            print(f"Step {step+1}: {response}")

            if "Final Answer:" in response:
                return response.split("Final Answer:")[-1].strip()

            # Parse Action and Action Input
            action_match = re.search(r"Action:\s*(\w+)", response)
            input_match = re.search(r"Action Input:\s*(.+)", response)

            if action_match and input_match:
                action, action_input = action_match.group(1), input_match.group(1).strip()
                if action in self.tools:
                    observation = self.tools[action](action_input)
                    self.history.append(f"Observation: {observation}")
                else:
                    self.history.append(f"Observation: Tool '{action}' not found.")
        return "Execution limit reached without final answer."
