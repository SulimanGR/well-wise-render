function calculate() {
    const gender = document.getElementById('gender').value;
    const age = parseFloat(document.getElementById('age').value);
    const height = parseFloat(document.getElementById('height').value);
    const weight = parseFloat(document.getElementById('weight').value);
    const activityMultiplier = parseFloat(document.getElementById('activity').value);
    const goal = document.getElementById('goal').value;

    if (!age || !height || !weight || age <= 0 || height <= 0 || weight <= 0) {
        alert("Please enter valid values for all fields.");
        return;
    }

    // Mifflin-St Jeor Equation for BMR
    let bmr;
    if (gender === 'male') {
        bmr = 10 * weight + 6.25 * height - 5 * age + 5;
    } else {
        bmr = 10 * weight + 6.25 * height - 5 * age - 161;
    }

    // Adjust daily calorie needs based on activity level
    let dailyCalories = bmr * activityMultiplier;

    // Adjust calorie intake based on goal
    if (goal === "lose") {
        dailyCalories -= 500; // reduce 500 calories for weight loss
    } else if (goal === "gain") {
        dailyCalories += 500; // add 500 calories for weight gain
    }

    // Daily protein needs (recommended 1.6 - 2.2 g/kg of body weight)
    const dailyProtein = weight * 1.8; // Average protein need

    // Display results
    document.getElementById('result').innerHTML = `
        <p><strong>Daily Calorie Needs:</strong> ${Math.round(dailyCalories)} kcal</p>
        <p><strong>Daily Protein Needs:</strong> ${Math.round(dailyProtein)} g</p>
    `;
}