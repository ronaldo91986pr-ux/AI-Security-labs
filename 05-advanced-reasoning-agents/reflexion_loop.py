class ReflexionAgent:
    def __init__(self, actor_llm, evaluator_llm):
        self.actor = actor_llm
        self.evaluator = evaluator_llm
        self.memory = []

    def execute_task(self, task: str):
        attempts = 0
        feedback = ""
        while attempts < 3:
            prompt = f"Task: {task}\nPrior Reflection: {feedback}\nGenerate Solution:"
            solution = self.actor(prompt)

            # Evaluate output
            eval_prompt = f"Task: {task}\nProposed Solution: {solution}\nIs this solution correct and safe? Answer PASS or provide critique:"
            evaluation = self.evaluator(eval_prompt)

            if "PASS" in evaluation:
                return solution
            else:
                feedback = evaluation
                self.memory.append((solution, feedback))
                attempts += 1
        return "Failed to produce a verified solution within execution budget."
