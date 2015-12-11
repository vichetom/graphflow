from math import sqrt
from scipy.optimize import fmin_l_bfgs_b


def HWT(x, m, m2, forecast, alpha = None,  gamma = None,delta=None,initial_values_optimization=[0.1, 0.2, 0.2]):
   
   Y = x[:]
   test_series = []
   if (alpha == None or gamma == None):
 
      boundaries = [(0, 1), (0, 1), (0,1)]
      train_series = Y[:-m2*1]
      test_series = Y[-m2*1:]
      #print train_series
      #print test_series
      Y = train_series
      func = RMSE
      parameters = fmin_l_bfgs_b(func, x0 = initial_values_optimization, args = (train_series, (m,m2), test_series), bounds = boundaries, approx_grad = True,factr=10**3)
      alpha, gamma, delta = parameters[0]
   

   a = [sum(Y[0:m]) / float(m)]
   s = [Y[i] / a[0] for i in range(m)]
   s2 = [Y[i] / a[0] for i in range(0,m2,m)]
   y = [a[0] + s[0] + s2[0]]
   
   for i in range(len(Y) + forecast+len(test_series)): 
      if i >= len(Y):
         Y.append(a[-1]+  s[-m] + s2[-m2])
      a.append(alpha * (Y[i] - s2[i] - s[i]) + (1 - alpha) * (a[i]))
      s.append(delta *  (Y[i] - a[i] - s2[i]) + (1 - delta) * s[i])
      s2.append(gamma * (Y[i] - a[i] - s[i]) + (1 - gamma) * s2[i])
      y.append(a[i + 1] +  s[i + 1] + s2[i + 1])
         
  
   return Y[-forecast:], (alpha, gamma, delta), y[:-forecast]

def RMSE(params, *args):
   forecast, next_prediction = ParamsEstimation(params,*args)
   test_data = args[2]
   train = args[0]
   rmse_outofsample = sum([(m - n) ** 2 for m, n in zip(test_data, forecast)]) / len(test_data)
   rmse_insample = sum([(m - n) ** 2 for m, n in zip(train, next_prediction)]) / len(train)
   
   #rmse = sqrt(sum([(m - n) ** 2 for m, n in zip(Y, y[:-1])]) / len(Y))

   return rmse_insample + rmse_outofsample

      

def ParamsEstimation(params, *args):
   train = args[0][:]
   m = args[1]
   test_data = args[2]
   alpha, gamma, delta = params
   forecast, params, next_prediction = HWT(train, m[0],m[1], len(test_data), alpha=alpha,gamma=gamma,delta=delta)
   
   return forecast, next_prediction
      




if __name__ == "__main__":
   values = list(xrange(30))
   #print values
   res = HWT(values, 2, 2*5, 5, alpha = None,  gamma = None,delta=None, initial_values_optimization=[0.1, 0.2, 0.2])

   print res
